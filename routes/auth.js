import { Router } from 'express'
import { decodeUserFromToken, checkAuth } from '../middleware/auth.js'
import * as authCtrl from '../controllers/auth.js'

const router = Router()

/*---------- Public Routes ----------*/
router.post('/signup', authCtrl.signup)
router.post('/login', authCtrl.login)
router.post('/generate-registration-options', authCtrl.generateRegistrationOptionsResponse)
router.post('/verify-registration', authCtrl.verifyRegistration)
router.post('/generate-authentication-options', authCtrl.generateAuthenticationOptionsResponse)
router.post('/verify-authentication', authCtrl.verifyAuthentication)

/*---------- Protected Routes ----------*/
router.use(decodeUserFromToken)
router.post('/change-password', checkAuth, authCtrl.changePassword)

export { router }
