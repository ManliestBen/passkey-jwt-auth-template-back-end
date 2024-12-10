import jwt from 'jsonwebtoken'

import { User } from '../models/user.js'
import { Profile } from '../models/profile.js'
import { Credential } from '../models/credential.js'
import { generateAuthenticationOptions, generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server'

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
    userName: user.name,
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

  req.session.currentChallenge = options.challenge

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
    res.json(verification)
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

export { signup, login, changePassword, generateRegistrationOptionsResponse, verifyRegistration }
