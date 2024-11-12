const express = require('express');
const morgan = require('morgan');
// eslint-disable-next-line import/no-extraneous-dependencies
const rateLimit = require('express-rate-limit');
// eslint-disable-next-line import/no-extraneous-dependencies
const helmet = require('helmet');
// eslint-disable-next-line import/no-extraneous-dependencies
const mongoSanitize = require('express-mongo-sanitize');
// eslint-disable-next-line import/no-extraneous-dependencies
const xss = require('xss-clean');
// eslint-disable-next-line import/no-extraneous-dependencies
const hpp = require('hpp');

const globalErrorHandler = require('./Controllers/errorController');
const userRouter = require('./Routes/UsersRoutes');
const tourRouter = require('./Routes/ToursRoutes');
const reviewRouter = require('./Routes/ReviewRoutes');
const AppError = require('./Utils/appError');

const app = express();

//-------GLOBAL MIDDLEWARES-------//
// <<<<<------Set Security HTTP header------>>>>>
app.use(helmet());

// <<<<<------Development logging------>>>>>

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// <<<<<------Limit request from same IP------>>>>>
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many request from this IP, please try again in an hour',
});

app.use('/api', limiter);

// <<<<<------Body parser, reading data from body into req.body------>>>>>

app.use(express.json({ limit: '10kb' }));

// <<<<<------Data sanitization against NoSQL query injection------>>>>>

app.use(mongoSanitize());

// <<<<<------Data sanatization against XSS------>>>>>

app.use(xss());

// <<<<<------Prevent parameter pollution------>>>>>

app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsQuantity',
      'ratingsAverage',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  }),
);

// <<<<<------Serving static files------>>>>>

app.use(express.static(`${__dirname}/public`));

// <<<<<------Test middleware------>>>>>

app.use((req, res, next) => {
  req.reqestTime = new Date().toISOString();
  // console.log(req.headers);

  next();
});

//--------ROUTES--------//

app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

//--------START SERVER--------//

module.exports = app;
