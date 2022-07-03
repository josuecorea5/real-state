import express from 'express';
import { forgotPasswordForm, loginForm, registerForm, userRegister,confirmEmail, resetPassword,testToken,newPassword, login } from '../controllers/userController.js';

const route = express.Router();

route.get('/login', loginForm);
route.post('/login',login)

//register routes
route.get('/register', registerForm);
route.post('/register', userRegister);
route.get('/confirm/:token', confirmEmail);
route.get('/forgotPassword', forgotPasswordForm);
route.post('/forgotPassword', resetPassword);
route.get('/forgot-password/:token', testToken);
route.post('/forgot-password/:token', newPassword);

export default route;