const nodemailer = require('nodemailer');
const dotenv = require("dotenv")
dotenv.config()

const pass = process.env.APP_PWD
const user = process.env.MAIL

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: `${user}`,
        pass: `${pass}`,
    },
});

const sendMail = async (email, otp) => {
    const mailOptions = {
        from: process.env.MAIL,
        to: email,
        subject:'Your OTP Code For Kalam Application ',
        text:`Your OTP code is ${otp}. It will expire in 5 minutes.`
    };

    try {
        let info = await transporter.sendMail(mailOptions);
        console.log('Email sent: ' + info.response);
        return info
    } catch (error) {
        console.error('Error sending email:', error);
    }


};

module.exports = sendMail;