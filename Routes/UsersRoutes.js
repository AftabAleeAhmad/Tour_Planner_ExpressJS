const express = require('express');
const UsersControler = require('../Controllers/UsersController');
const authControler = require('../Controllers/authController');

const router = express.Router();

router.post('/signup', authControler.signup);
router.post('/login', authControler.login);

router.post('/forgotPassword', authControler.forgetPassword);
router.patch('/resetPassword/:token', authControler.resetPassword);
router.patch(
  '/updateMyPassword',
  authControler.protect,
  authControler.updatePassword,
);

router.patch('/updateMe', authControler.protect, UsersControler.updateMe);
router.delete('/deleteMe', authControler.protect, UsersControler.deleteMe);

router
  .route('/')
  .get(UsersControler.getAllUsers)
  .post(UsersControler.createUser);
router
  .route('/:id')
  .get(UsersControler.getUser)
  .patch(UsersControler.updateUser)
  .delete(UsersControler.deleteUser);

module.exports = router;
