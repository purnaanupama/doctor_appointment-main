import express from 'express';
import { loginUser, logout, registerUser, getUser } from '../controllers/userController.js';
import {
    validateRegisterUser,
    validateLoginUser
  } from '../middleware/formValidation.js';
import { verifyToken } from '../middleware/authMiddlware.js';

const router = express.Router();

router.post('/register',validateRegisterUser, registerUser);
router.post('/login',validateLoginUser, loginUser);
router.post('/logout',verifyToken, logout);
router.get('/current-user',verifyToken,getUser);

export default router;