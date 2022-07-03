import { check, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import { User } from "../models/User.js";
import { generateId, generateJWT } from '../helpers/tokens.js';
import { emailRegister, emailRestPassword } from '../helpers/emails.js';

const loginForm = (req, res) => {
  res.render('auth/login', {
    csrfToken: req.csrfToken(),
    page: 'Iniciar Sesión'
  })
}

const login = async(req,res) => {
  await check('email').isEmail().withMessage('email requerido').run(req);
  await check('password').notEmpty().withMessage('password requerido').run(req);

  let result = validationResult(req);

  if(!result.isEmpty()){
    const errors = result.array().map(error => {
      return { name: error.param, msg:error.msg}
    })
    
    return res.render('auth/login', {
      page: 'Login',
      csrfToken: req.csrfToken(),
      errors: errors
    })
  }

  const { email, password } = req.body;

  const user = await User.findOne({where: {email}});

  if(!user) {
    return res.render('auth/login', {
      page: 'Login',
      csrfToken: req.csrfToken(),
      message: [{msg: 'El usuario no existe'}]
    })
  }

  if(!user.confirm) {
    return res.render('auth/login', {
      page: 'Login',
      csrfToken: req.csrfToken(),
      message: [{msg: 'Tu cuenta no ha sido confirmada'}]
    })
  }

  if(!user.verifyPassword(password)) {
    return res.render('auth/login', {
      page: 'Login',
      csrfToken: req.csrfToken(),
      message: [{msg: 'Password incorrecto'}],
      email: req.body.email
    })
  }

  const token = generateJWT({id: user.id, name: user.name});

  return res.cookie('_token',token,{
    httpOnly: true
  }).redirect('/my-properties')
  
}

const registerForm = (req,res) => {
  res.render('auth/register', {
    page: 'Crear Cuenta',
    csrfToken: req.csrfToken()
  })
}

const userRegister = async (req,res) => {
  const { name, email, password } = req.body;
  await check('name').notEmpty().withMessage('El nombre no puede ir vacío').run(req);
  await check('email').isEmail().withMessage('Ingresa un email válido').run(req);
  await check('password').isLength({min: 6}).withMessage('Password debe contener al menos 6 carácteres').run(req);
  await check('repite_password').equals(password).withMessage('Passwords deben ser iguales').run(req);

  let result = validationResult(req);
  console.log(req.body)

  if(!result.isEmpty()){
    const errors = result.array().map(error => {
      return { name: error.param, msg:error.msg}
    })
    
    console.log(errors);
    return res.render('auth/register', {
      page: 'Crear Cuenta',
      csrfToken: req.csrfToken(),
      errors: errors,
      user: {
        name: req.body.name,
        email: req.body.email
      }
    })
  }
  const userExist = await User.findOne({where: {email}})

  if(userExist) {
    return res.render('auth/register', {
      page: 'Crear cuenta',
      csrfToken: req.csrfToken(),
      message: [{msg: 'El usuario ya está registrado'}],
      user: {
        name: req.body.name,
        email: req.body.email
      }
    })
  }

  const user = await User.create({
    name,
    email,
    password,
    token: generateId()
  })

  emailRegister({
    name: user.name,
    email: user.email,
    token: user.token
  })

  res.render('template/message', {
    page: 'Cuenta creada con éxito',
    message: 'Revisa tu email para verificar tu cuenta :)'  
  })
}

const confirmEmail = async (req,res) => { 
  const { token } = req.params; 
  const searchToken = await User.findOne({where: {token}});

  if(!searchToken) {
    return res.render('auth/confirmAccount', {
      page: 'Error de token',
      message: 'Hubo un error, tu token no es válido, intenta de nuevo :(',
      error: true
    })
  }
  searchToken.token = null;
  searchToken.confirm = true;
  searchToken.save();

  return res.render('auth/confirmAccount', {
    page: 'Email confirmado',
    message: 'Tu email ha sido confirmado'
  })
}

const forgotPasswordForm  = (req,res) => {
  res.render('auth/forgotPassword', {
    page: 'Recupera tu contraseña',
    csrfToken: req.csrfToken(),
  })
}

const resetPassword = async (req,res) => {
  const { email } = req.body;
  await check('email').isEmail().withMessage('Ingresa un email válido').run(req);

  let result = validationResult(req);

  if(!result.isEmpty()){
    const errors = result.array().map(error => {
      return { name: error.param, msg:error.msg}
    })
    return res.render('auth/forgotPassword', {
      page: 'Recupera tu contraseña',
      csrfToken: req.csrfToken(),
      errors: errors,
    })
  }

  const emailExist = await User.findOne({where: {email}})

  if(!emailExist) {
    return res.render('auth/forgotPassword', {
      page: 'Recupera tu contraseña',
      csrfToken: req.csrfToken(),
      message: [{msg: 'El email no es válido'}]
    })
  }

  emailExist.token = generateId();
  await emailExist.save();

  emailRestPassword({
    name: emailExist.name,
    email: emailExist.email,
    token: emailExist.token
  })

  res.render('template/message', {
    page: 'Reestablecer password',
    message: 'Revisa tu email para reesablecer tu password :)'  
  })
  
}

const testToken = async (req,res) => {
  const { token } = req.params;

  const user = await User.findOne({where: {token}});
  if(!user) {
    return res.render('auth/confirmAccount', {
      page: 'Reestablece tu password',
      message: 'Hubo un error al validar tu token, intenta de nuevo :)',
      error: true
    })
  }

  res.render('auth/resetPassword', {
    pagina: 'Reestablecer password',
    csrfToken: req.csrfToken()
  })
}

const newPassword = async (req,res) => {
  const {token} = req.params;
  const { password } = req.body;
  await check('password').isLength({min: 6}).withMessage('Password debe contener al menos 6 carácteres').run(req);
  let result = validationResult(req);

  if(!result.isEmpty()){
    const errors = result.array().map(error => {
      return { name: error.param, msg:error.msg}
    })
    return res.render('auth/resetPassword', {
      page: 'Recupera tu contraseña',
      csrfToken: req.csrfToken(),
      errors: errors,
    })
  }

  const user = await User.findOne({where: {token}});
  user.token = null;
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(password, salt);
  user.save();

  return res.render('auth/confirmAccount', {
    page: 'Cambiar password',
    message: 'Tu password ha sido actualizado con éxito :)'
  })

}

export { loginForm, registerForm, forgotPasswordForm, userRegister, confirmEmail, resetPassword, testToken, newPassword, login }