import jwt from 'jsonwebtoken'

import { User } from '../models/user.js'
import { Profile } from '../models/profile.js'
import { Credential } from '../models/credential.js'
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server'

async function signup(req, res) {
  try {
    if (!process.env.SECRET) throw new Error('no SECRET in back-end .env')

    const user = await User.findOne({ email: req.body.email })
    if (user) throw new Error('Account already exists')

    const newProfile = await Profile.create(req.body)
    req.body.profile = newProfile._id
    const newUser = await User.create(req.body)

    const token = createJWT(newUser)
    res.status(200).json({ token })
  } catch (err) {
    console.log(err)
    try {
      if (req.body.profile) {
        await Profile.findByIdAndDelete(req.body.profile)
      }
    } catch (err) {
      console.log(err)
      return res.status(500).json({ err: err.message })
    }
    res.status(500).json({ err: err.message })
  }
}

async function login(req, res) {
  try {
    if (!process.env.SECRET) throw new Error('no SECRET in back-end .env')

    const user = await User.findOne({ email: req.body.email })
    if (!user) throw new Error('User not found')

    const isMatch = await user.comparePassword(req.body.password)
    if (!isMatch) throw new Error('Incorrect password')

    const token = createJWT(user)
    res.json({ token })
  } catch (err) {
    handleAuthError(err, res)
  }
}

async function changePassword(req, res) {
  try {
    const user = await User.findById(req.user._id)
    if (!user) throw new Error('User not found')

    const isMatch = user.comparePassword(req.body.password)
    if (!isMatch) throw new Error('Incorrect password')

    user.password = req.body.newPassword
    await user.save()

    const token = createJWT(user)
    res.json({ token })
    
  } catch (err) {
    handleAuthError(err, res)
  }
}

async function generateRegistrationOptionsResponse(req, res) {
  // add edge cases to handle a user registering an additional key
  let user = await User.findOne({email: req.body.email})
  if (!user) {
    // user doesn't exist, create a new one
    const newProfile = await Profile.create(req.body)
    req.body.profile = newProfile._id
    user = await User.create(req.body)
  }
  const credentials = await Credential.find({userId: user._id})
  const opts = {
    rpName: process.env.RP_NAME,
    rpID: process.env.RP_ID,
    userName: user.email,
    timeout: 60000,
    attestationType: 'none',
    excludeCredentials: credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      // authenticatorAttachment: 'platform'
    },
    supportedAlgorithmIDs: [-7, -257],
  }

  const options = await generateRegistrationOptions(opts)
  // options.userId = user._id

  user.currentChallenge = options.challenge
  user.webAuthId = options.user.id

  await user.save()

  // req.session.currentChallenge = options.challenge

  res.send(options)
}

async function verifyRegistration(req, res)  {
  const user = await User.findOne({ webAuthId: req.body.webAuthId })
  let verification
  console.log(user)
  try {
    const opts = {
      response: req.body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.FRONT_END_ORIGIN,
      expectedRPID: process.env.RP_ID,
      requireUserVerification: false,
    }
    verification = await verifyRegistrationResponse(opts)
    const { registrationInfo } = verification;
    const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo
    console.log(credential.publicKey)
    console.log(verification)
    // consider adding code here to delete the user/profile if registration is not validated
    const newCredential = Credential.create({
      credId: registrationInfo.credential.id,
      userId: user._id,
      publicKey: Array.from(registrationInfo.credential.publicKey),
      type: registrationInfo.credentialType,
      transports: registrationInfo.credential.transports,
      counter: registrationInfo.credential.counter,
      aaguId: registrationInfo.aaguid,
      attestationType: registrationInfo.fmt
    })
    user.currentChallenge = null
    await user.save()
    if (verification.verified) {
      const token = createJWT(user)
      res.status(200).json({ token })
    } else {
      throw new Error("Verification failed")
    }
  } catch (err) {
    console.log(err)
  }
}

async function generateAuthenticationOptionsResponse(req, res) {
  try {
    console.log(req.body)
    const user = await User.findOne({ email: req.body.email })
    console.log(user)
    const userPasskeys = Credential.find({ userId: user._id })
    const options = await generateAuthenticationOptions({
      rpId: process.env.RP_ID,
      allowCredentials: (await userPasskeys).map(passkey => ({
        id: passkey.credId,
        transports: passkey.transports
      }))
    })

    user.currentChallenge = options.challenge
    
    await user.save()
    
    console.log(options)
    
    res.send(options)
  } catch (err) {
    console.log(err)
  }
}

async function verifyAuthentication(req, res) {
  const user = await User.findOne({ email: req.body.email })
  console.log(user)
  const passkey = await Credential.findOne({ credId: req.body.id })
  console.log(passkey)
  if (!passkey) {
    throw new Error(`Could not find passkey ${req.body.id} for user ${user._id}`);
  }
  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.FRONT_END_ORIGIN,
      expectedRPID: process.env.RP_ID,
      credential: {
        id: passkey.credId,
        publicKey: new Uint8Array(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports
      }
    })
    console.log(verification)
    if (verification.verified) {
      const token = createJWT(user)
      res.status(200).json({ token })
    } else {
      throw new Error("Verification failed")
    }
  } catch (err) {
    console.log(err)
  }
}


/* --== Helper Functions ==-- */

function handleAuthError(err, res) {
  console.log(err)
  const { message } = err
  if (message === 'User not found' || message === 'Incorrect password') {
    res.status(401).json({ err: message })
  } else {
    res.status(500).json({ err: message })
  }
}

function createJWT(user) {
  return jwt.sign({ user }, process.env.SECRET, { expiresIn: '24h' })
}

export { signup, login, changePassword, generateRegistrationOptionsResponse, verifyRegistration, generateAuthenticationOptionsResponse, verifyAuthentication }
