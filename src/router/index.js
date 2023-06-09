const Router = require('express').Router
const userController = require('../controllers/userController')
const {body} = require('express-validator')
const authMiddleware = require('../middlewares/authMiddleware')

const router = new Router()

router.post('/register',
  body('email').isEmail(),
  body('password').isLength({min: 3, max: 20}),
  userController.register)
router.post('/login', userController.login)
router.post('/logout', userController.logout)
router.get('/activate/:link', userController.activate)
router.get('/refresh', userController.refresh)
router.get('/users', authMiddleware, userController.getUsers)

module.exports = router
