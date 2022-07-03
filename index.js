import express from 'express';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import userRoutes from './routes/userRoutes.js';
import { db } from './config/db.js'

const app = express();

app.use(express.urlencoded({extended: true}));

app.use(cookieParser());

app.use(csurf({cookie: true}));

//connection db

try {
  await db.authenticate();
  db.sync();
  console.log('Connection has been established successfully');
} catch (error) {
  console.log(error);
}

const PORT = process.env.PORT || 3000;

app.set('view engine', 'pug');
app.set('views','./views');

//use public folder
app.use(express.static('public'))

app.use('/auth', userRoutes);

app.listen(PORT, () => {
  console.log(`Server running at port ${PORT}`);
})