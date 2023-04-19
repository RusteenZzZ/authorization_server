const jwt = require('jsonwebtoken')
const tokenModel = require('../models/TokenModel')

class TokenService {
  validateAccessToken (token) {
    try {
      const userData = jwt.verify(token, process.env.JWT_ACCESS_TOKEN)
      return userData
    } catch (e) {
      return null
    }
  }

  validateRefreshToken (token) {
    try {
      const userData = jwt.verify(token, process.env.JWT_REFRESH_TOKEN)
      return userData
    } catch (e) {
      return null
    }
  }

  generateToken (payload) {
    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_TOKEN, {expiresIn: '15s'})
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_TOKEN, {expiresIn: '30s'})
    return {
      accessToken,
      refreshToken
    }
  }

  async saveToken (userId, refreshToken) {
    const tokenData = await tokenModel.findOne({user: userId})
    if (tokenData) {
      tokenData.refreshToken = refreshToken
      return tokenData.save()
    }
    const token = await tokenModel.create({user: userId, refreshToken})
    return token
  }

  async removeToken (refreshToken) {
    const tokenData = await tokenModel.deleteOne({refreshToken})
    return tokenData
  }

  async findToken (refreshToken) {
    const tokenData = await tokenModel.findOne({refreshToken})
    return tokenData
  }
}

module.exports = new TokenService()
