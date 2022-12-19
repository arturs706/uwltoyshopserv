use axum_macros::debug_handler;
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow};
use uuid::Uuid;
use crate::AppState;
use axum::{Json, extract::{State, Path}, response::IntoResponse, http::StatusCode};
use serde_json::json;

#[derive(Serialize, Deserialize, FromRow, Debug)]

pub struct Orders {
    total: f64,
    userid: Uuid
}

#[derive(Debug, Serialize, FromRow, Deserialize)]

pub struct OrderResponse {
    orderid: i64
}

#[derive(Debug, Serialize, FromRow, Deserialize)]

pub struct OrderItems {
    productid: Uuid,
    orderidretr: i64,
    quantity: i32
}
#[derive(Debug, Serialize, FromRow, Deserialize)]

pub struct OrderItemsResponse {
    created_at: chrono::DateTime<chrono::Utc>,
    prodname: String,
    price: String,
    proddescr: String,
    imageone: String,
    quantity: i64,
    total: bigdecimal::BigDecimal
}


#[debug_handler]
pub async fn corder(State(state): State<AppState>, req: Json<Orders>) -> impl IntoResponse {
    let created_at = chrono::Utc::now();
    let response = sqlx::query_as::<_, OrderResponse>(
        "INSERT INTO orderdet(total, userid, created_at) VALUES ($1, $2, $3) RETURNING orderid")
        .bind(&req.total)
        .bind(&req.userid)
        .bind(&created_at)
        .fetch_all(&state.database.db)
        .await;
    match response {
        Ok(orderid) => (StatusCode::CREATED, Json(json!({
            "response": orderid
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Something went wrong",
            "error": e.to_string(),
        }))),
    }
}




#[debug_handler]
pub async fn createorderdetails(State(state): State<AppState>, req: Json<OrderItems>) -> impl IntoResponse {
    let mut tx = state.database.db.begin().await.unwrap();
    let response = sqlx::query(
        "INSERT INTO listitems(productid, orderidretr, quantity) VALUES ($1, $2, $3)")
        .bind(&req.productid)
        .bind(&req.orderidretr)
        .bind(&req.quantity)
        .execute(&mut tx)
        .await;
    match response {
        Ok( _ ) => {
            let response = sqlx::query("UPDATE products 
            SET availableqty = availableqty - $1
            WHERE productid = $2")
            .bind(&req.quantity)
            .bind(&req.productid)
            .execute(&mut tx)
            .await;
            match response {
                Ok(_) => {
                    tx.commit().await.unwrap();
                    (StatusCode::OK, Json(json!({
                        "status": "Success",
                        "message": "Order created successfully"
                    })))
                },
                Err(e) => {
                    tx.rollback().await.unwrap();
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "status": "error",
                        "message": "Something went wrong",
                        "error": e.to_string(),
                    })))
                }
    }
}
        Err(e) => {
            tx.rollback().await.unwrap();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "status": "error",
                "message": "Something went wrong",
                "error": e.to_string(),
            })))
        }
    }
}


#[debug_handler]
pub async fn selectallorders(State(state): State<AppState>, Path(usid): Path<Uuid>) -> impl IntoResponse {
    let response = sqlx::query_as::<_,OrderResponse>(
        "SELECT orderid FROM orderdet where userid = $1")
        .bind(&usid)
        .fetch_all(&state.database.db)
        .await;
    match response {
        Ok(orderid) => (StatusCode::OK, Json(json!({
            "response": orderid
        }))),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "status": "error",
                "message": "Something went wrong",
                "error": e.to_string(),
            })))
        }
    }
}

pub async fn selectsingleorder(State(state): State<AppState>, Path(orderid): Path<i64>) -> impl IntoResponse {
    let response = sqlx::query_as::<_, OrderItemsResponse>(
        "SELECT 
        listitems.quantity, 
        orderdet.created_at, orderdet.total,
        products.prodname, products.price, products.proddescr,
        productimages.imageone
        FROM listitems
        INNER JOIN orderdet ON listitems.orderidretr = orderdet.orderid
        INNER JOIN products ON listitems.productid = products.productid
        INNER JOIN productimages ON products.prodsku = productimages.prodskuid
        where orderid = $1")
        .bind(&orderid)
        .fetch_all(&state.database.db)
        .await;
    match response {
        Ok(response) => (StatusCode::OK, Json(json!({
            "response": response
        }))),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "status": "error",
                "message": "Something went wrong",
                "error": e.to_string(),
            })))
        }
    }
}