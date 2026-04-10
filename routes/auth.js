import { Router } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { v4 as uuid } from 'uuid'

const router = Router()
const JWT_SECRET = 'zhimianxing-admin-secret-2024'
const MAX_FAILED_ATTEMPTS = 3 // 超过N次需填验证码
const LOCK_DURATION_MINUTES = 30

function generateCode() {
  return Math.floor(1000 + Math.random() * 9000).toString()
}

function generateToken(user) {
  return jwt.sign(
    { userId: user.id, phone: user.phone },
    JWT_SECRET,
    { expiresIn: '7d' }
  )
}

function cleanupExpiredCodes() {
  const now = Date.now()
  db.codes = db.codes.filter(c => c.expiresAt > now)
}

// ==================== 发送验证码 ====================
router.post('/send-code', async (req, res) => {
  const { phone, type } = req.body
  if (!phone || phone.length !== 11) {
    return res.json({ success: false, error: '请输入正确的手机号' })
  }

  cleanupExpiredCodes()

  const code = generateCode()
  const expiresAt = Date.now() + 5 * 60 * 1000 // 5分钟

  db.codes.push({ phone, code, type, expiresAt, used: false })

  // 演示模式：直接返回验证码（生产环境替换为真实短信通道）
  console.log(`[演示] ${phone} 验证码: ${code} (${type})`)
  console.log('生产环境请接入容联云/阿里云短信')

  res.json({ success: true, expiresIn: 300, demoCode: code })
})

// ==================== 账号密码登录 ====================
router.post('/login-phone', async (req, res) => {
  const { phone, password, captcha } = req.body

  const user = db.users.get(phone)
  if (!user) {
    return res.json({ success: false, error: '账号不存在', code: 'NOT_FOUND' })
  }

  // 检查是否被锁定
  if (user.lockedUntil && Date.now() < user.lockedUntil) {
    const leftMin = Math.ceil((user.lockedUntil - Date.now()) / 60000)
    return res.json({
      success: false,
      error: `账户已锁定，请 ${leftMin} 分钟后再试`,
      code: 'ACCOUNT_LOCKED',
      lockMinutes: LOCK_DURATION_MINUTES,
      attempts: user.failedAttempts
    })
  }

  // 需要验证码但没填
  if (user.failedAttempts >= MAX_FAILED_ATTEMPTS && !captcha) {
    return res.json({
      success: false,
      error: `登录失败 ${user.failedAttempts} 次，请填写验证码`,
      code: 'NEED_CAPTCHA',
      attempts: user.failedAttempts
    })
  }

  // 验证密码
  const match = await bcrypt.compare(password, user.passwordHash)
  if (!match) {
    user.failedAttempts = (user.failedAttempts || 0) + 1

    if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      user.lockedUntil = Date.now() + LOCK_DURATION_MINUTES * 60 * 1000
      return res.json({
        success: false,
        error: `密码错误次数过多，账户已锁定 ${LOCK_DURATION_MINUTES} 分钟`,
        code: 'ACCOUNT_LOCKED',
        lockMinutes: LOCK_DURATION_MINUTES,
        attempts: user.failedAttempts
      })
    }

    return res.json({
      success: false,
      error: `手机号或密码错误（剩余 ${MAX_FAILED_ATTEMPTS - user.failedAttempts} 次）`,
      code: 'INVALID_PASSWORD',
      attempts: user.failedAttempts
    })
  }

  // 登录成功
  user.failedAttempts = 0
  user.lockedUntil = null

  // 检查是否需要设置密码
  if (user.needSetPassword) {
    const token = generateToken(user)
    return res.json({ success: true, token, needSetPassword: true, user: { phone: user.phone } })
  }

  const token = generateToken(user)
  db.loginLogs.push({ phone, success: true, time: new Date().toISOString() })

  res.json({
    success: true,
    token,
    user: { id: user.id, phone: user.phone }
  })
})

// ==================== 验证验证码 ====================
router.post('/verify-code', (req, res) => {
  const { phone, code, type } = req.body
  cleanupExpiredCodes()

  const record = db.codes.find(c =>
    c.phone === phone &&
    c.code === code &&
    c.type === type &&
    !c.used &&
    c.expiresAt > Date.now()
  )

  if (!record) {
    return res.json({ success: false, error: '验证码错误或已过期' })
  }

  record.used = true
  res.json({ success: true })
})

// ==================== 设置密码（首次/重置） ====================
router.post('/set-password', async (req, res) => {
  const { phone, password } = req.body

  if (!phone || !password) {
    return res.json({ success: false, error: '参数错误' })
  }

  if (password.length < 8 || password.length > 16) {
    return res.json({ success: false, error: '密码长度需8-16位' })
  }

  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return res.json({ success: false, error: '需同时包含字母和数字' })
  }

  const user = db.users.get(phone)
  if (!user) {
    return res.json({ success: false, error: '用户不存在' })
  }

  user.passwordHash = await bcrypt.hash(password, 10)
  user.needSetPassword = false
  user.failedAttempts = 0

  const token = generateToken(user)
  res.json({ success: true, token, user: { id: user.id, phone: user.phone } })
})

// ==================== 重置密码（忘记密码） ====================
router.post('/reset-password', async (req, res) => {
  const { phone, code, password } = req.body

  cleanupExpiredCodes()
  const record = db.codes.find(c =>
    c.phone === phone && c.code === code && c.type === 'forget' && !c.used && c.expiresAt > Date.now()
  )

  if (!record) {
    return res.json({ success: false, error: '验证码错误或已过期' })
  }

  record.used = true

  if (password.length < 8 || password.length > 16) {
    return res.json({ success: false, error: '密码长度需8-16位' })
  }

  const user = db.users.get(phone)
  if (user) {
    user.passwordHash = await bcrypt.hash(password, 10)
    user.needSetPassword = false
    user.failedAttempts = 0
    user.lockedUntil = null
  }

  res.json({ success: true })
})

// ==================== 微信扫码绑定手机 ====================
router.post('/bind-phone', async (req, res) => {
  const { phone, code } = req.body

  cleanupExpiredCodes()
  const record = db.codes.find(c =>
    c.phone === phone && c.code === code && c.type === 'login' && !c.used && c.expiresAt > Date.now()
  )

  if (!record) {
    return res.json({ success: false, error: '验证码错误或已过期' })
  }

  record.used = true

  let user = db.users.get(phone)
  if (!user) {
    // 新用户，自动创建
    user = {
      id: uuid(),
      phone,
      passwordHash: null,
      failedAttempts: 0,
      lockedUntil: null,
      needSetPassword: true,
      createdAt: new Date().toISOString()
    }
    db.users.set(phone, user)
  }

  if (user.needSetPassword) {
    const token = generateToken(user)
    return res.json({ success: true, token, needSetPassword: true, user: { id: user.id, phone: user.phone } })
  }

  const token = generateToken(user)
  res.json({ success: true, token, user: { id: user.id, phone: user.phone } })
})

export default router
