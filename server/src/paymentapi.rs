use crate::AppState;
use axum::{extract::State, Json, response::IntoResponse,http::StatusCode};
use stripe::{
    AttachPaymentMethod, CardDetailsParams, Client, CreateCustomer, CreatePaymentIntent,
    CreatePaymentMethod, CreatePaymentMethodCardUnion, Currency, Customer, PaymentIntent,
    PaymentIntentConfirmParams, PaymentMethod, PaymentMethodTypeFilter, UpdatePaymentIntent};
use serde::{Deserialize, Serialize};
use serde_json::json;

// use axum::{Json, extract::{Path, Extension}, response::IntoResponse, http::{StatusCode, HeaderMap}};

#[derive(Serialize, Deserialize, Debug)]

pub struct Payment {
    customername : String,
    customeremail: String,
    paymentamount: i64,
    paymentcard: String,
    paymentcardexpyr: i32,
    paymentcardexpmonth: i32,
    cvc: String
}
#[derive(Serialize, Deserialize, Debug)]

pub struct PaymentIntentId {
    pub customerid: String,
    pub customername: String,
    pub customeremail: String,
    pub paymentamount: i64
}

pub async fn paymentintent(State(state): State<AppState>, req: Json<PaymentIntentId>) -> impl IntoResponse {
    let client = Client::new(&state.stripetoken.stripetoken);
    let customer = Customer::create(
        &client,
        CreateCustomer {
            name: Some(&req.customername),
            email: Some(&req.customeremail),
            metadata: Some(
                [("async-stripe".to_string(), "true".to_string())].iter().cloned().collect(),
            ),

            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut create_intent = CreatePaymentIntent::new(req.paymentamount, Currency::GBP);
    create_intent.payment_method_types = Some(vec!["card".to_string()]);
    create_intent.metadata = Some([("db_id".to_string(),req.customerid.to_string())].iter().cloned().collect());
    create_intent.customer = Some(customer.id);
    let payment_intent = PaymentIntent::create(&client, create_intent).await;
    
    match payment_intent {
        Ok(response) => (StatusCode::OK, Json(json!({
            "clientSecret": response.client_secret,
            "status": response.status,
            "publishableKey": &state.stripepubtoken.stripepubtoken
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Something went wrong",
            "error": e.to_string(),
        }))),
    }

}

pub async fn pay(State(state): State<AppState>, req: Json<Payment>) -> impl IntoResponse {

    let client = Client::new(&state.stripetoken.stripetoken);
    let customer = Customer::create(
        &client,
        CreateCustomer {
            name: Some(&req.customername),
            email: Some(&req.customeremail),
            metadata: Some(
                [("async-stripe".to_string(), "true".to_string())].iter().cloned().collect(),
            ),

            ..Default::default()
        },
    )
    .await
    .unwrap();
    println!("created a customer at https://dashboard.stripe.com/test/customers/{}", customer.id);

    let payment_intent = {
        let mut create_intent = CreatePaymentIntent::new(req.paymentamount, Currency::GBP);
        create_intent.payment_method_types = Some(vec!["card".to_string()]);
        create_intent.statement_descriptor = Some("TEST");
        create_intent.metadata =
            Some([("db_id".to_string(),"uuid".to_string())].iter().cloned().collect());

        PaymentIntent::create(&client, create_intent).await.unwrap()
    };

    let payment_method = {
        let pm = PaymentMethod::create(
            &client,
            CreatePaymentMethod {
                type_: Some(PaymentMethodTypeFilter::Card),
                card: Some(CreatePaymentMethodCardUnion::CardDetailsParams(CardDetailsParams {
                    number: req.paymentcard.to_string(), // UK visa
                    exp_year: req.paymentcardexpyr,
                    exp_month: req.paymentcardexpmonth,
                    cvc: Some(req.cvc.to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        PaymentMethod::attach(
            &client,
            &pm.id,
            AttachPaymentMethod { customer: customer.id.clone() },
        )
        .await
        .unwrap();

        pm
    };

    let payment_intent = PaymentIntent::update(
        &client,
        &payment_intent.id,
        UpdatePaymentIntent {
            payment_method: Some(payment_method.id),
            customer: Some(customer.id), // this is not strictly required but good practice to ensure we have the right person
            ..Default::default()
        },
    )
    .await
    .unwrap();


    let response = PaymentIntent::confirm(
        &client,
        &payment_intent.id,
        PaymentIntentConfirmParams { ..Default::default() },
    )
    .await;
    match response {
        Ok(response) => (StatusCode::OK , Json(json!({
            "clientSecret": response.client_secret,
            "status": response.status,
            "publishableKey": &state.stripepubtoken.stripepubtoken
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Something went wrong",
            "error": e.to_string(),
        }))),
    }

}











#[derive(Deserialize, Serialize, Debug)]
pub struct HandleStripePaymentBody {
    pub cancel_uri: String,
    pub success_uri: String,
}


// pub async fn checkout_session(Form(data): Form<HandleStripePaymentBody>, Json(req): Json<Payment>, state: Extension<Arc<AppState>>) -> impl IntoResponse {
//     let client = Client::new(&state.stripetoken.stripetoken);
//     let mut checkout_session_params = CreateCheckoutSession::new(&data.cancel_uri, &data.success_uri);

//     let mut line_item = CreateCheckoutSessionLineItems::default();
//     let mut price_data = CreateCheckoutSessionLineItemsPriceData::default();
//     let mut product_data = CreateCheckoutSessionLineItemsPriceDataProductData::default();
//     product_data.name = "Realy cool course".to_owned();
//     price_data.currency = Currency::GBP;
//     price_data.product_data = Some(product_data);
//     price_data.unit_amount = Some(99);
//     line_item.price_data = Some(price_data);
//     line_item.quantity = Some(1);
//     checkout_session_params.line_items = Some(vec![line_item]);
//     checkout_session_params.mode = Some(CheckoutSessionMode::Payment);
    
//     let checkout_session = match CheckoutSession::create(&client, checkout_session_params).await {
//         Ok(checkout_session) => checkout_session,
//         Err(error) => {
//             dbg!(error);
//             return Redirect::to(&data.cancel_uri);
//         }
//     };
//     let redirect_uri = checkout_session.url.unwrap();
//     Redirect::to(&redirect_uri)
// }





