const UserModel = require('../models/UserModel')
const bcrypt = require('bcrypt')
const uuid = require('uuid')
const mailService = require('./mailService')
const tokenService = require('./tokenService')
const UserDTO = require('../dto/UserDTO')
const ApiError = require('../exceptions/apiError')

class UserService {
  async register (email, password) {
    const candidate = await UserModel.findOne({email})
    if (candidate) {
      throw ApiError.BadRequest(`User with such email is already registered`)
    }

    const hashedPassword = await bcrypt.hash(password, 3)
    const activationLink = uuid.v4()
    const user = await UserModel.create({email, password: hashedPassword, activationLink})

    await mailService.sendActivationLink(email, `${process.env.API_URL}/api/activate/${activationLink}`)

    const userDTO = new UserDTO(user)
    const tokens = tokenService.generateToken({...userDTO})
    await tokenService.saveToken(user._id, tokens.refreshToken)

    return {
      ...tokens,
      user: userDTO
    }
  }

  async activate (activationLink) {
    const user = await UserModel.findOne({activationLink})
    if (!user) {
      throw ApiError.BadRequest('Wrong activation link!')
    }

    user.isActivated = true
    await user.save()
  }

  async login (email, password) {
    const user = await UserModel.findOne({email}) 

    if (!user) {
      throw ApiError.BadRequest('Wrong email or password')
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password)

    if(!isPasswordCorrect) {
      throw ApiError.BadRequest('Wrong email or password')
    }

    const userDTO = new UserDTO(user)
    const tokens = tokenService.generateToken({...userDTO})

    await tokenService.saveToken(userDTO.id, tokens.refreshToken)
    return {
      ...tokens,
      user: userDTO
    }
  }

  async logout (refreshToken) {
    const token = await tokenService.removeToken(refreshToken)
    return token
  }

  async refresh (refreshToken) {
    if (!refreshToken) {
      throw ApiError.UnauthorizedError()
    }
    const userData = tokenService.validateRefreshToken(refreshToken)
    const tokenFromDB = await tokenService.findToken(refreshToken)
    if (!userData || !tokenFromDB) {
      throw ApiError.UnauthorizedError()
    }

    const user = await UserModel.findById(userData.id)
    const userDTO = new UserDTO(user)
    const tokens = tokenService.generateToken({...userDTO})

    await tokenService.saveToken(userDTO.id, tokens.refreshToken)
    return {...tokens, user: userDTO}
  }

  async getAllUsers () {
    const users = await UserModel.find()
    return users
  }
}

module.exports = new UserService()
