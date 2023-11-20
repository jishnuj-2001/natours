const mongoose = require('mongoose');
const slugify = require('slugify');
// const validator = require('validator');
// const User = require('./userModel');

const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name'],
      unique: true,
      trim: true,
      maxlength: [40, 'A tour name can only have atmost 40 charecters '],
      minlength: [10, 'A tour name must have atleast 10 charecters  '],
      // validate: [validator.isAlpha, 'Tour name must only contain charecters'],
    },
    slug: {
      type: String,
    },
    duration: {
      type: Number,
      required: [true, 'A tour must have a duration'],
    },
    maxGroupSize: {
      type: Number,
      required: [true, 'A tour must have a group size'],
    },
    difficulty: {
      type: String,
      required: [true, 'A tour should have a difficulty'],
      enum: {
        values: ['easy', 'medium', 'difficult'],
        message: 'Difficulty is either easy,medium, or difficult',
      },
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, 'Rating must be higher than 1.0'],
      max: [5, 'Rating must be lower than 5.0'],
      set: (val) => Math.round(val * 10) / 10,
    },
    ratingsQuantity: {
      type: Number,
      default: 0,
    },
    price: {
      type: Number,
      required: [true, 'A tour must have a price'],
    },
    priceDiscount: {
      type: Number,
      validate: {
        message: 'Discount price ({VALUE}) must be lower than actual price',
        validator: function (val) {
          return val < this.price;
        },
      },
    },
    summary: {
      type: String,
      trim: true,
      required: [true, 'A tour summary is required'],
    },
    description: {
      type: String,
      trim: true,
    },
    imageCover: {
      type: String,
      required: [true, 'A tour cover image is required'],
    },
    images: [String],
    createdAt: {
      type: Date,
      default: Date.now(),
      select: false,
    },
    startDates: [Date],
    secretTour: {
      type: Boolean,
      default: false,
    },
    startLocation: {
      //GeoJSON
      type: {
        type: String,
        default: 'Point',
        enum: ['Point'],
      },
      coordinates: [Number],
      address: String,
      description: String,
    },
    locations: [
      {
        type: {
          type: String,
          default: 'Point',
          enum: ['Point'],
        },
        coordinates: [Number],
        address: String,
        description: String,
        day: Number,
      },
    ],
    guides: [{ type: mongoose.Schema.ObjectId, ref: 'User' }],
  },
  { toJSON: { virtuals: true } },
  { toObject: { virtuals: true } },
);
// tourSchema.index({ price: 1 });
//Creating index
tourSchema.index({ startLocation: '2dsphere' });
tourSchema.index({ price: 1, ratingsAverage: -1 });
tourSchema.virtual('durationWeeks').get(function () {
  return this.duration / 7;
});
//Virtual popluate
tourSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'tour',
  localField: '_id',
});
//Document middleware runs before .save() and .create()
// tourSchema.pre('save', async function (next) {
//   const guidesPrmoises = this.guides.map(async (id) => await User.findById(id));
//   this.guides = await Promise.all(guidesPrmoises);
//   next();
// });
tourSchema.pre('save', function (next) {
  this.slug = slugify(this.name, { lower: true });
  next();
});
// tourSchema.post('save', function (doc, next) {
//   console.log(doc);
//   next();
// });

//QUERY MIDDLEWARE
tourSchema.pre(/^find/, function (next) {
  this.find({ secretTour: { $ne: true } });
  this.start = Date.now();
  next();
});
tourSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'guides',
    select: '-__v -passwordChangedAt',
  });
  next();
});
// tourSchema.pre('aggregate', function (next) {
//   this.pipeline().unshift({ $match: { secretTour: { $ne: true } } });
//   next();
// });
tourSchema.post(/^find/, function (doc, next) {
  // console.log(`Query took ${Date.now() - this.start} milliseconds to complete`);
  next();
});
//AGGREGATION MIDDLEWARE
const Tour = new mongoose.model('Tour', tourSchema);
module.exports = Tour;
