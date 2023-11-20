/* eslint-disable*/

import axios from 'axios';
import { showAlert, hideAlert } from './alert';
const stripe = Stripe(
  'pk_test_51OEC13SHa4JCRMN2DBFXrnBhp3yvZ9JDL3tXv4pIkGXg6wXNUrZjwjXkqD5yFxUBFnMb7BNbZdLGctTJ8iaD26zn00XoHKRoGV'
);
export const bookTour = async tourId => {
  try {
    // 1) Get checkout session from API
    const session = await axios(
      `http://127.0.0.1:3000/api/v1/bookings/checkout-session/${tourId}`
    );
    console.log(session);

    // 2) Create checkout form + chanre credit card
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id
    });
  } catch (err) {
    console.log(err);
    showAlert('error', err);
  }
};
