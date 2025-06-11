const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

async function sendPasswordResetEmail(email, resetToken) {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password.html?token=${resetToken}&email=${email}`;
    
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Restablecer contraseña - www.controldeconductores.com',
        html: `
            <h1>Restablecer su contraseña</h1>
            <p>Ha solicitado restablecer su contraseña.</p>
            <p>Haga clic en el siguiente enlace para continuar:</p>
            <a href="${resetLink}">Restablecer contraseña</a>
            <p>Este enlace expirará en 1 hora.</p>
            <p>Si no solicitó restablecer su contraseña, ignore este correo.</p>
        `
    };

    return transporter.sendMail(mailOptions);
}

module.exports = { sendPasswordResetEmail };