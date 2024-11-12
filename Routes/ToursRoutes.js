const express = require('express');
const tourController = require('../Controllers/ToursController');
const authControler = require('../Controllers/authController');
const reviewControler = require('../Controllers/reviewController');

const router = express.Router();

// router.param("id", tourController.checkID);

router
  .route('/top-5-cheap')
  .get(tourController.aliesTopTours, tourController.getAllTours);

router.route('/tour-stats').get(tourController.getTourStats);
router.route('/monthly-plan/:year').get(tourController.getMonthlyPlan);

router
  .route('/')
  .get(authControler.protect, tourController.getAllTours)
  .post(tourController.createTour);
router
  .route('/:id')
  .get(tourController.getTour)
  .patch(tourController.updateTour)
  .delete(
    authControler.protect,
    authControler.restrictTo('admin', 'lead-guide'),
    tourController.deleteTour,
  );

router
  .route('/:tourId/reviews')
  .post(
    authControler.protect,
    authControler.restrictTo('user'),
    reviewControler.createReview,
  );

module.exports = router;
