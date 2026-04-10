import express from 'express'
import cors from 'cors'
import authRoutes from './routes/auth.js'

const app = express()
const PORT = 3001

app.use(cors())
app.use(express.json())

// 内存数据库（演示用）
global.db = {
  users: new Map(),
  codes: [],
  loginLogs: [],
  stats: {
    totalUsers: 12847,
    activeDevices: 3291,
    todayOrders: 486,
    todayRevenue: 28540
  }
}

// 初始化测试管理员
const bcrypt = await import('bcryptjs')
;(async () => {
  const hash = await bcrypt.default.hash('admin123', 10)
  db.users.set('13800138000', {
    id: '1',
    phone: '13800138000',
    passwordHash: hash,
    failedAttempts: 0,
    lockedUntil: null,
    needSetPassword: false,
    createdAt: new Date().toISOString()
  })
  console.log('测试账号已创建: 13800138000 / admin123')
})()

app.use('/api/auth', authRoutes)

app.get('/api/dashboard/stats', (req, res) => {
  res.json(db.stats)
})

app.listen(PORT, '0.0.0.0', () => {
  console.log(`智眠星管理后台服务已启动: http://localhost:${PORT}`)
})
