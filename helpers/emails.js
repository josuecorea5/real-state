import nodemailer from 'nodemailer';

const emailRegister = async(data) => {
  const transport = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const {name, email, token} = data;

  await transport.sendMail({
    from: 'BienesRaices.com',
    to: email,
    subject: 'Confirma tu cuenta en BienesRaices.com',
    text: 'Confirma tu cuenta en BienesRaices.com',
    html: `
      <p>Hola ${name}, comprueba tu cuenta :) .</p>

      <p> Tu cuenta ya está lista, solo debes confirmar con el siguiente enlace: <a href="${process.env.URL_SERVER}${process.env.PORT ?? 3000}/auth/confirm/${token}" >Confirmar Cuenta.</a> </p>

      <p>Si no has creado una cuenta, ignora este email.</p>
    `
  })
}

const emailRestPassword = async(data) => {
  const transport = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const {name, email, token} = data;

  await transport.sendMail({
    from: 'BienesRaices.com',
    to: email,
    subject: 'Reestablece tu password en BienesRaices.com',
    text: 'Reestablece tu password en BienesRaices.com',
    html: `
      <p>Hola ${name}, reestablece tu password :) .</p>

      <p> Para cambiar tu contraseña sigue el siguiente enlace: <a href="${process.env.URL_SERVER}${process.env.PORT ?? 3000}/auth/forgot-password/${token}" >Cambiar password.</a> </p>

      <p>Si no has solicitado cambiar tu contraseña, ignora este email.</p>
    `
  })
}

export { emailRegister, emailRestPassword }