const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const dotenv = require("dotenv")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const multer = require("multer")
const grid = require("gridfs-stream")
const { GridFsStorage } = require('multer-gridfs-storage');
const { GridFSBucket } = require("mongodb")
const sendMail = require('./emailService');
const { storeOTP, verifyOTP } = require('./otpService');

dotenv.config()
const port = process.env.PORT || 5000

const musername = encodeURIComponent(process.env.MONGO_USERNAME)
const mpassword = encodeURIComponent(process.env.MONGO_PASSWORD)

const path = `mongodb+srv://${musername}:${mpassword}@blogwebsite.rid2fzm.mongodb.net/?retryWrites=true&w=majority&appName=BlogWebsite`
const { Schema } = mongoose
const app = express();


app.use(express.json())
app.use(cors())


const connect = () => {
    mongoose.connect(path)
        .then(() => {
            console.log("connected to mongo ")
        }).catch((error) => {
            console.log(" error connecting to mongo ", error)
        })

}

connect();

const admin = new Schema
    (
        {
            name: String,
            username: String,
            password: String,
            email: String
        }
    )

const tokenSchema = new Schema
    (
        {
            token:
            {
                type: String,
                required: true
            }
        }
    )

const info = new mongoose.model('newusers', admin)
const tokendetail = new mongoose.model('token', tokenSchema)

// sign up  

app.post('/signup', async (req, res) => {
    try {
        const { name, username, password, email } = req.body;
        const salt = await bcrypt.genSalt();
        const hashedpwd = await bcrypt.hash(password, salt)
        const newadmin = new info({ name, username, password: hashedpwd, email })
        const user = await newadmin.save()
        res.status(200).json(user)
    }
    catch (error) {
        res.status(500).json({ message: 'server not supported ', error })
    }

})


// login 


// otp 

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    try {
        const otp = await storeOTP(email);
        await sendMail(email, otp);
        res.status(200).send('OTP sent successfully');
    } catch (error) {
        res.status(500).json({ message: 'Error sending OTP', error });
    }
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const isValid = await verifyOTP(email, otp);
        if (isValid) {
            res.status(200).send('OTP verified');
        } else {
            res.status(400).send('Invalid or expired OTP');
        }
    } catch (error) {
        res.status(500).json({ message: 'Error verifying OTP', error });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const query = await info.findOne({ username })

    if (query) {
        const validPassword = await bcrypt.compare(password, query.password);
        if (validPassword) {
            const accesstoken = jwt.sign(query.toJSON(), process.env.SECRET_KEY, { expiresIn: '1h' })

            const refreshtoken = jwt.sign(query.toJSON(), process.env.REFRESH_KEY)

            const newtoken = new tokendetail({ token: refreshtoken })
            await newtoken.save();

            return res.status(200).json({ accesstoken, name: query.name, refreshtoken, username: query.username })
        }
        else {
            res.status(404).json({ message: " Inavlaid Credentials  " })
        }
    }
    else {
        return res.status(404).json({ message: " User Not Found  " })
    }
})

// upload image 

const storage = new GridFsStorage({
    url: path,
    options: { useNewUrlParser: true, useUnifiedTopology: true },
    file: (req, file) => {
        const match = ["image/png", "image/jpg"];

        if (match.indexOf(file.mimetype) === -1) {
            return `${Date.now()}-blog-${file.originalname}`;

        }

        const filename = `${Date.now()}-blog-${file.originalname}`;


        return {
            bucketName: "photos",
            filename: filename,
        };
    }

})

storage.on('connection', (db) => {
    console.log('GridFS connected');
}).on('connectionFailed', (err) => {
    console.error('GridFS connection failed', err);
});

const upload = multer({ storage });
const url = 'https://kalam-backend-7ov5.onrender.com'

app.post('/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(404).json({ message: 'File not Found ' })
    }

    const imgUrl = `${url}/file/${req.file.filename}`

    return res.status(200).json(imgUrl)
})

// retain the url given by mongo and then show the image to client 

const conn = mongoose.connection;
let gfs, gridfSBucket;
conn.once('open', () => {
    gridfSBucket = new mongoose.mongo.GridFSBucket(conn.db, {
        bucketName: 'fs'
    })

    gfs = grid(conn.db, mongoose.mongo)
    gfs.collection('fs')
})
const getImage = async (req, res) => {
    try {
        const file = await gfs.files.findOne({ filename: req.params.filename })
        const readstream = gridfSBucket.openDownloadStream(file._id)
        readstream.pipe(res)
    } catch (error) {
        return res.status(500).json({ msimageg: error.message })
    }
}

app.get('/file/:filename', getImage)



// saving post 

// model 

const postSchema = new Schema(
    {
        title:
        {
            type: String,
            required: true,
            unique: true
        },

        description:
        {
            type: String,
            required: true,
        },
        picture:
        {
            type: String,
        },
        username:
        {
            type: String,
            required: true,
        },
        createdDate:
        {
            type: Date,
        },
        category:
        {
            type: String,
            required: true,
        },
    }
)

const post = new mongoose.model('post', postSchema)



// api 
const authenticatetoken = (req, res, next) => {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ msg: 'Token is missing ' })
    }

    jwt.verify(token, process.env.SECRET_KEY, (error, user) => {
        if (error) {
            return res.status(403).json({ msg: 'Invalid Token' })
        }

        req.user = user;
        next();
    })


}

app.post('/save', authenticatetoken, async (req, res) => {
    try {
        const newpost = await new post(req.body);
        await newpost.save();
        console.log("Post saved successfully:", newpost);
        return res.status(200).json(' Post saved successfully ')
    } catch (error) {
        console.error("Error Saving post:", error);
        return res.status(500).json('Error Saving post ')
    }

})


// getting all post to display 

app.get('/postfetch', authenticatetoken, async (req, res) => {
    try {
        let postf = await post.find({})
        return res.status(200).json(postf)
    } catch (error) {
        return res.status(500).json({ msg: error.message })
    }
})

// category post to display 
app.post("/categorypost", authenticatetoken, async (req, res) => {
    const category = req.headers.category;
    if (!category) {
        return res.status(400).json({ error: "Category header is required" });
    }

    try {
        const posts = await post.find({ category });
        res.json(posts);
    } catch (error) {
        res.status(500).json({ error: "An error occurred while fetching posts" });
    }
});

// get specific post in detail 
app.get('/getpostbyid/:id', authenticatetoken, async (req, res) => {
    try {
        const sppost = await post.findById(req.params.id)
        return res.status(200).json(sppost)
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})

// update specific post 

app.put('/update/:id', authenticatetoken, async (req, res) => {
    try {
        const sppost = await post.findById(req.params.id)
        const username = req.user.username;
        if (!sppost) {
            return res.status(404).json({ msg: ' Post not found ' })
        }

        const updatedPost = {
            ...req.body,
            username: username
        };
        await post.findByIdAndUpdate(req.params.id, { $set: updatedPost })
        return res.status(200).json({ msg: " Post updated successfully " })
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})


// delete post 
app.delete('/delete/:id', authenticatetoken, async (req, res) => {
    try {
        const dpost = await post.findByIdAndDelete(req.params.id)
        return res.status(200).json({ msg: 'Post deleted successfully ' })
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})

// comment 

// new model for comment 

const commentSchema = new mongoose.Schema(
    {
        name:
        {
            type: String,
            required: true
        },

        postId:
        {
            type: String,
            required: true
        },
        date:
        {
            type: Date,
            required: true
        },
        comments:
        {
            type: String,
            required: true
        }
    }
)

const comment = new mongoose.model('comment', commentSchema)





// api 
app.post('/newcomment', authenticatetoken, async (req, res) => {
    try {
        let response = await new comment(req.body)
        response.save();

        res.status(200).json({ msg: ' comment saved successfully' })
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})

// get all comments 

app.get('/getcomments/:id', authenticatetoken, async (req, res) => {
    try {
        const response = await comment.find({ postId: req.params.id })

        return res.status(200).json(response)
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})

// delete the comment 

app.delete('/deletecomment/:id', authenticatetoken, async (req, res) => {
    try {
        const result = await comment.findByIdAndDelete(req.params.id);
        res.status(200).json({ msg: ' Comment deleted successfully' })
    } catch (error) {
        res.status(500).json({ msg: error.message })
    }
})

app.get('/', (req, res) => {
    res.send(" Hello World ")
})

app.listen(port, (req, res) => {
    console.log(`server started on ${port}`)
})
