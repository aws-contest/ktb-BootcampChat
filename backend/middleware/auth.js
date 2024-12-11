// backend/middleware/auth.js
const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/keys');
const SessionService = require('../services/sessionService');

// 기본 인증 - JWT 토큰만 검증
const auth = async (req, res, next) => {
  const start = process.hrtime();
  
  try {
    const token = req.header('x-auth-token') || req.query.token;
    if (!token) {
      return res.status(401).json({
        success: false,
        message: '인증 토큰이 없습니다.'
      });
    }

    try {
      // JWT 토큰 검증만 수행
      const decoded = jwt.verify(token, jwtSecret);
      
      // 필요한 정보만 저장하도록 최적화
      req.user = {
        id: decoded.user.id
      };
      next();
      
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: '토큰이 만료되었습니다.'
        });
      }

      if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: '유효하지 않은 토큰입니다.'
        });
      }

      throw err;
    }

  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(500).json({
      success: false,
      message: '서버 오류가 발생했습니다.'
    });
  } finally {
    const [seconds, nanoseconds] = process.hrtime(start);
    const duration = seconds * 1000 + nanoseconds / 1000000;
    console.log(`Auth middleware execution time: ${duration}ms`);
  }
};

// 엄격한 인증 - JWT 토큰 + 세션 검증
const strictAuth = async (req, res, next) => {
  const start = process.hrtime();
  
  try {
    const token = req.header('x-auth-token') || req.query.token;
    const sessionId = req.header('x-session-id') || req.query.sessionId;

    if (!token || !sessionId) {
      return res.status(401).json({
        success: false,
        message: '인증 정보가 없습니다.'
      });
    }

    try {
      // JWT 토큰 검증
      const decoded = jwt.verify(token, jwtSecret);
      req.user = decoded.user;

      // 세션 검증 추가
      const validationResult = await SessionService.validateSession(decoded.user.id, sessionId);
      
      if (!validationResult.isValid) {
        return res.status(401).json({
          success: false,
          code: validationResult.error,
          message: validationResult.message
        });
      }

      next();

    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: '토큰이 만료되었습니다.'
        });
      }

      if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: '유효하지 않은 토큰입니다.'
        });
      }

      throw err;
    }
    
  } catch (err) {
    console.error('Strict auth middleware error:', err);
    res.status(500).json({
      success: false,
      message: '서버 오류가 발생했습니다.'
    });
  } finally {
    const [seconds, nanoseconds] = process.hrtime(start);
    const duration = seconds * 1000 + nanoseconds / 1000000;
    console.log(`Strict auth middleware execution time: ${duration}ms`);
  }
};

module.exports = { auth, strictAuth };