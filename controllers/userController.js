import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';

//User register
//user new reducer
export const registerUser = async (req, res, next) => {
  //Check is any validation error are there
  const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, mobileNumber, role } = req.body;
  
    try {
      //Check any user already registered using same email
      let user = await User.findOne({ 
        where: { email }});
      if (user) {
        return res.status(400).json({
            status: false,
            message: 'User already exist'
        });
      }
      //Hashing the password
      const hashedPassword = await bcrypt.hash(password, 10);
      if (!hashedPassword) {
        return res.status(400).json({
          status: false,
          message: 'Password hashing error'
        });
      }
  
      //Adding user data to the users table
      user = await User.create({ username, email, password:hashedPassword, mobileNumber, role });
  
      //Create jwt token
      const payload = { id: user.id, role: user.role };
      const token = jwt.sign(
        payload, 
        process.env.JWT_SECRET_KEY, 
        {expiresIn: '1hr'}
      )
  
      //Setting up JWT token in cookie
      res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 3600000) //Token expiretion time (1 hour)
      });
  
      return res.status(201).json({
        status: true,
        token,
        message: 'User registered successfully'
      });
    } catch (error) {
      next(error);
    }
  };


  export const loginUser = async (req, res, next) => {
    // Check if any validation errors are there
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const { email, password } = req.body;
  
    try {
      // Check email as user credentials
      const user = await User.findOne({
        where: { email },
        attributes: ['id', 'email','password', 'role']  // Include 'id' and 'role'
      });
  
      if (!user) {
        return res.status(400).json({
          status: false,
          message: 'User not found',
        });
      }
  
      // Check password as user credentials
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({
          status: false,
          message: 'Username or password incorrect',
        });
      }
  
      // Create JWT token with user ID and role in payload
      const payload = { id: user.id, role: user.role };
      const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: '1hr' });
  
      // Setting up JWT token in cookie
      res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 3600000), // Token expiration time (1 hour)
      });
  
      return res.status(200).json({
        status: true,
        token,
        data: { id: user.id, email },
        message: 'User is logged in successfully',
      });
    } catch (error) {
      next(error);
    }
  };
  
  //User logout functionality
export const logout = async (req, res, next) => {
  try {
    // Clear the token cookie by setting it with an immediate expiration
    res.clearCookie('token', {
      httpOnly: true,
      secure: true
    });

    return res.status(200).json({
      success: 'success',
      message: 'Logged out successfully.'
    });
  } catch (error) {
    next(error);
  }
};

export const getUser = async (req, res, next)=>{
  try {
    const user = req.user;
    const user_data = await User.findByPk(user)
    console.log(user);
    const userPlain = user_data.get({ plain: true });
    const {id,...rest} = userPlain;
    return res.status(200).json({
      success: 'success',
      data:rest
    });
  } catch (error) {
      next(error)
  }
}