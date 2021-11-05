require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const User = require('./models/User')

const app = express()
app.use(express.json())


function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    res.status(401).json({msg: 'Acesso negado'})
  }

  try {
    const SECRET = process.env.SECRET

    jwt.verify(token, SECRET)

    next()
  }catch (err) {
    res.status(400).json({msg: 'token invalido'})
  }

}


app.get('/', (req, res) => {
  res.status(200).json({msg: 'Hello World'})
})

app.post('/register', async(req, res) => {
  const { name, email, password, confirm } = req.body

  if (!name) {
    res.status(401).json({msg: 'insira um name'})
  }

  if (!email) {
    res.status(401).json({msg: 'insira um email'})
  } else {
    await User.findOne({email: email})
      .then((user) => {
        if (user) {
          res.status(401).json({msg: 'email ja registrado'})
        }
      }).catch(err => console.log(err.message))
  }

  if (!password) {
    res.status(401).json({msg: 'insira um password'})
  }

  if (!confirm) {
    res.status(401).json({msg: 'insira um confirm)'})
  } else if (confirm != password) {
    res.status(401).json({msg: 'confirm invalido'})
  }

  const salt = await bcrypt.genSalt(12)
  const hash = await bcrypt.hash(password, salt)

  try {
    await new User({name, email, password: hash}).save()
    res.status(200).json({msg: 'Usuario registrado'})
  } catch(err) {
    console.log(err.message)
    res.status(500).json({msg: 'Ocorreu um erro tente mais tarde'})
  }
})

app.post('/login', (req, res) => {
  const { email, password } = req.body

  const user = User.findOne({ email: email})
    .then(async user => {
      const msg = 'Senha ou email invalidos'

      if (!user) {
        res.status(401).json({msg: msg})
      } 
      
      const check = await bcrypt.compare(password, user.password)

      if (!check) {
        res.status(401).json({msg: msg})
      }

      try {
        const SECRET = process.env.SECRET
        const token = jwt.sign({ id: user._id }, SECRET )

        res.status(200).json({msg: 'logado', token: token})
      } 
      catch (err) {
        console.error(err.message)
        res.status(500).json({msg: 'Erro no interno tente mais tarde'})
      }
    })
})

app.get('/find/:id', checkToken, (req, res) => {
  const id = req.params.id

  User.findById(id, '-password')
    .then(user => {
      if (!user) {
        res.status(404).json({msg: 'Usuasrio não existe'})
      } else {
        res.status(200).json({ user })
      }
    }).catch(err => {
      res.status(404).json({msg: 'Usuasrio não existe'})
    })
})


const PORT = process.env.PORT

mongoose.connect(`mongodb://localhost/auth`)
  .then(() => {
    app.listen(PORT, () => console.log('Server running'))
  })
  .catch(err => console.log(err))
