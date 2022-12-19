use axum::{
    extract::{State, Path},
    Json,
    response::IntoResponse,
    http::{StatusCode, HeaderMap},  
};
use serde::{Serialize, Deserialize};
use sqlx::{self, FromRow};
use uuid::Uuid;
use serde_json::json;
use crate::AppState;
use core::fmt;
use std::borrow::Cow;
use tower_cookies::{Cookie, Cookies};
use jsonwebtoken::{Header, Algorithm, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use argon2::{password_hash::{rand_core::OsRng, SaltString},Argon2, PasswordVerifier};
use argon2::PasswordHash;
use argon2::PasswordHasher;
use axum_macros::debug_handler;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};


//User model for get all users
#[derive(Serialize, FromRow, Debug)]
struct User {
    usid : Uuid,
    fullname: String,
    username: String,
    dob: String,
    gender: String,
    mob_phone: String,
    email: String,
    created_at: chrono::DateTime<chrono::Utc>,
    address: String,
    city: String,
    postcode: String
}

//User model for register
#[derive(Serialize, Deserialize, Debug)]
pub struct UserReg {
    fullname: String,
    username: String,
    dob: String,
    gender: String,
    mob_phone: String,
    email: String,
    passwd: String,
    address: String,
    city: String,
    postcode: String
}

#[derive(Deserialize, FromRow, Debug)]
pub struct UserLoginUuid{
    usid: Uuid,
    passwd: String,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]

pub struct EditReg {
    fullname: Option<String>,
    username: Option<String>,
    dob: Option<String>,
    gender: Option<String>,
    mob_phone: Option<String>,
    email: Option<String>,
    passwd: Option<String>,
    passwdconf: Option<String>,
    address: Option<String>,
    city: Option<String>,
    postcode: Option<String>
}


#[derive(Deserialize, FromRow, Debug)]

pub struct UserPassReset{
    email: String,
    usid: Uuid,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]

pub struct UserPassResetTwo{
    usid: Uuid
}

#[derive(Serialize, Deserialize, FromRow, Debug)]

pub struct UserPassResetThree{
    email: String
}

pub enum Role {
    User,
    Admin,
}

impl Role { pub fn _from_str(role: &str) -> Role {
    match role { 
        "Admin" =>  
                Role::Admin, 
        _ =>    Role::User, 
    }}}

impl fmt::Display for Role { fn fmt(&self, f: &mut fmt::Formatter<'_>) ->
    fmt::Result { 
    match self { 
    Role::User => write!(f, "User"), 
    Role::Admin => write!(f, "Admin"),
}}}
#[derive(Debug, Serialize, Deserialize)]

pub struct ClaimsAccessToken { 
    pub sub: Uuid,
    pub exp: i64, 
    pub iat: i64, 
    pub role: String,
    }

impl ClaimsAccessToken { 
    pub fn new (id: Uuid, role: Role ) -> Self { 
    let iat = Utc::now();
    let exp = iat + Duration::hours(24);
    Self {
        sub: id,
        iat: iat.timestamp(),
        exp: exp.timestamp(),
        role: role.to_string(),
}}}
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimsRefreshToken { 
    pub sub: Uuid,
    pub exp: i64, 
    pub iat: i64, 
    pub role: String,
    }


impl ClaimsRefreshToken { 
    pub fn new (id: Uuid, role: Role ) -> Self { 
    let iat = Utc::now();
    let exp = iat + Duration::hours(72);
    Self {
        sub: id,
        iat: iat.timestamp(),
        exp: exp.timestamp(),
        role: role.to_string(),
}}}

#[derive(Deserialize, FromRow, Debug)]
pub struct UserLogin{
    email: String,
    passwd: String,
}


//ALL USERS route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//rALL USERS route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
pub async fn fetchusershandler(State(state): State<AppState>) -> impl IntoResponse {
    let response = sqlx::query_as::<_, User>("SELECT users.usid, users.fullname, users.username, users.dob, users.gender, users.mob_phone, users.email, users.created_at, useraddr.address, useraddr.city, useraddr.postcode
    FROM users
    INNER JOIN useraddr ON users.usid = useraddr.userid")
    .fetch_all(&state.database.db)
    .await;
    match response {
        Ok(users) => (StatusCode::OK , Json(json!({
            "users": users
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Something went wrong",
            "error": e.to_string(),
        }))),
    }
    
}
//reg route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//reg route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

pub async fn regroute(State(state): State<AppState>, req: Json<UserReg>) -> impl IntoResponse {
    let usid = sqlx::types::Uuid::from_u128(uuid::Uuid::new_v4().as_u128()); 
    let addrid = sqlx::types::Uuid::from_u128(uuid::Uuid::new_v4().as_u128()); 
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2.hash_password(req.passwd.as_bytes(), &salt).unwrap().to_string();
        let mut tx = state.database.db.begin().await.unwrap();
        let _cow = Cow::Borrowed("23505");
        let response = sqlx::query(
            "INSERT INTO users (usid, fullname, username, dob, gender, mob_phone, email, passwd, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(usid)
            .bind(&req.fullname)
            .bind(&req.username)
            .bind(&req.dob)
            .bind(&req.gender)
            .bind(&req.mob_phone)
            .bind(&req.email)
            .bind(password_hash)
            .bind(chrono::Utc::now())
            .execute(&mut tx)
            .await;
            match response {
                Ok( _ ) => {
                    let response = sqlx::query(
                        "INSERT INTO useraddr (addrid, userid, address, city, postcode) VALUES ($1, $2, $3, $4, $5)")
                        .bind(addrid)
                        .bind(usid)
                        .bind(&req.address)
                        .bind(&req.city)
                        .bind(&req.postcode)
                        .execute(&mut tx)
                        .await;

                        
                        match response {
                            Ok(_) => {
                                tx.commit().await.unwrap();
                                (StatusCode::OK, Json(json!({
                                    "status": "success",
                                    "message": "User registered successfully"
                                })))
                            },
                            Err(e) => match e {
                                
                                sqlx::Error::Database(e) => {
                                    tx.rollback().await.unwrap();
                                    match e.code() {
                                        Some(_cow) => (StatusCode::BAD_REQUEST, Json(json!({
                                            "status": "error",
                                            "message": "User already exists",
                                        }))),
                                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                            "status": "error",
                                            "message": "Something went wrong"
                                        }))),
                                    }
                                }
                                _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                    "status": "error",
                                    "message": "Something went wrong"
                                }))),
                            },
                        
                        }

                },
                Err(e) => match e {
                                
                    sqlx::Error::Database(e) => {
                        tx.rollback().await.unwrap();

                        match e.code() {
                            Some(_cow) => (StatusCode::BAD_REQUEST, Json(json!({
                                "status": "error",
                                "message": "User already exists",
                            }))),
                            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                "status": "error",
                                "message": "Something went wrong"
                            }))),
                        }
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "status": "error",
                        "message": "Something went wrong"
                    }))),
                },

        }

    }


//login user route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//login user route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    
    pub async fn loginuser(State(state): State<AppState>, cookies: Cookies, req: Json<UserLogin>) -> impl IntoResponse {
        let mut headers = HeaderMap::new();
    
        if req.passwd.is_empty() || req.email.is_empty(){
            return (StatusCode::BAD_REQUEST,headers, Json(json!({
                "status": "error",
                "message": "Email or password cannot be empty"
            })));
        }
        let _cow = Cow::Borrowed("23505");
        let response =  sqlx::query_as::<_, UserLoginUuid>("SELECT * FROM users where email = $1", )
        .bind(&req.email)
        .fetch_one(&state.database.db)
        .await;
        match response {
            Ok(user) => {    
                let parsed_hash = PasswordHash::new(&user.passwd).unwrap();
                let is_pass_valid = Argon2::default().verify_password(req.passwd.as_bytes(), &parsed_hash).is_ok();
                if is_pass_valid {
                
                    let role_access = if req.email == "aradionovs@yahoo.com" { Role::Admin } else { Role::User };
                    let role_refresh = if req.email == "aradionovs@yahoo.com" { Role::Admin } else { Role::User };
                    let access_secret = &state.accesstoken.accesstoken.as_bytes();
                    let access_token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &ClaimsAccessToken::new(user.usid, role_access),&EncodingKey::from_secret(access_secret)).unwrap();
                    let refresh_secret = &state.refreshtoken.refreshtoken.as_bytes();
                    let refresh_stoken = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &ClaimsRefreshToken::new(user.usid, role_refresh),&EncodingKey::from_secret(refresh_secret.as_ref())).unwrap();
                    // let bearertoken = format!("Bearer {}", access_token);
                    cookies.add(Cookie::build("Refresh Token", refresh_stoken.to_string())
                    .domain("axumtoyserver.shuttleapp.rs")
                    .path("/api/v1/users/login")
                    .secure(true)
                    .http_only(true)
                    .finish());
                    
                    headers.insert("Authorization", access_token.parse().unwrap());
                    (StatusCode::OK, headers, Json(json!({
                        "status": "success",
                        "message": "User logged in successfully",
                        "access_token": access_token.to_string(),
                        "refresh_token": refresh_stoken.to_string(),
                    })))
                } else {
                    (StatusCode::BAD_REQUEST, headers, Json(json!({
                        "status": "error",
                        "message": "Invalid email or password",
                    })))
                }
            }
            Err(e) => match e {
                sqlx::Error::Database(e) => {
                    match e.code() {
                        Some(_cow) => (StatusCode::BAD_REQUEST, headers, Json(json!({
                            "status": "error",
                            "message": "User already exists",
                        }))),
                        _ => (StatusCode::INTERNAL_SERVER_ERROR,headers, Json(json!({
                            "status": "error",
                            "message": "Something went wrong"
                        }))),
                    }
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR,headers, Json(json!({
                    "status": "error",
                    "message": "Something went wrong"
                }))),
            },
        }
        
    }
    
//Refresh token route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//Refresh token route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


#[debug_handler]
pub async fn refreshtokenhandler (State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let refresh_token = cookies.get("Refresh Token").unwrap();
    if refresh_token.value().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "status": "error",
            "message": "Refresh token is empty",
        })))
    } else {
        let refresh_token = refresh_token.value();
        let refresh_secret = &state.refreshtoken.refreshtoken.as_bytes();
        let validation = Validation::new(Algorithm::HS256);
        let refresh_token = jsonwebtoken::decode::<ClaimsAccessToken>(&refresh_token, &DecodingKey::from_secret(refresh_secret), &validation);
        match refresh_token {
            Ok(token) => {
                let access_secret = &state.accesstoken.accesstoken.as_bytes();
                let refresh_secret = &state.refreshtoken.refreshtoken.as_bytes();
                let usid = (token.claims.sub).to_string();
                let accessrole = if usid == "9dfdb6f8-6521-4ec4-b349-3a2c47d89269" { Role::Admin } else { Role::User };
                let refreshrole = if usid == "9dfdb6f8-6521-4ec4-b349-3a2c47d89269" { Role::Admin } else { Role::User };
                let access_token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &ClaimsAccessToken::new(token.claims.sub, accessrole),&EncodingKey::from_secret(access_secret)).unwrap();
                let refresh_token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &ClaimsAccessToken::new(token.claims.sub, refreshrole),&EncodingKey::from_secret(refresh_secret)).unwrap();
                cookies.add(Cookie::build("Refresh Token", refresh_token.to_string())
                .domain("axumtoyserver.shuttleapp.rs")
                .path("/api/v1/users/login")
                .secure(true)
                .http_only(true)
                .finish());
                (StatusCode::OK, Json(json!({
                    "status": "success",
                    "message": "Access token refreshed successfully",
                    "access_token": access_token.to_string(),
                    "access_token": refresh_token.to_string()
                })))
            }
            Err(e) => (StatusCode::BAD_REQUEST, Json(json!({
                "status": "error",
                "message": "Refresh token is invalid",
                "error": e.to_string(),
            })))
        }
    }
}


//Single userfetch route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//Single userfetch route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


pub async fn fetchsingleusershandler (State(state): State<AppState>, Path(usid): Path<Uuid>) -> impl IntoResponse {
    let response = sqlx::query_as::<_, User>(
    "SELECT 
    users.usid, users.fullname, users.username, users.dob, users.gender, users.mob_phone, users.email, users.created_at, useraddr.address, useraddr.city, useraddr.postcode
    FROM users
    INNER JOIN useraddr ON users.usid = useraddr.userid
    WHERE users.usid = $1")
    .bind(usid)
    .fetch_all(&state.database.db)
    .await;
    match response {
        Ok(users) => (StatusCode::OK , Json(json!({
            "users": users
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Something went wrong",
            "error": e.to_string(),
        }))),
    }
}

//Update user route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//Update user route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


pub async fn updateuserhandler(State(state): State<AppState>, Path(usid): Path<Uuid>, req: Json<EditReg>) ->  impl IntoResponse {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let my_bytes = req.passwd.clone().unwrap();
        let password_hash = argon2.hash_password(my_bytes.as_bytes(), &salt).unwrap().to_string();

        let mut tx = state.database.db.begin().await.unwrap();
        let _cow = Cow::Borrowed("23505");
        let response = sqlx::query(

    "
    UPDATE users 
    SET
    fullname = COALESCE(NULLIF($1, ''), fullname),
    username = COALESCE(NULLIF($2, ''), username),
    dob = COALESCE(NULLIF($3, ''), dob),
    gender = COALESCE(NULLIF($4, ''), gender),
    mob_phone = COALESCE(NULLIF($5, ''), mob_phone),
    email = COALESCE(NULLIF($6, ''), email),
    WHERE usid = $7 AND passwd = $8
    "

                    )
            .bind(&req.fullname)
            .bind(&req.username)
            .bind(&req.dob)
            .bind(&req.gender)
            .bind(&req.mob_phone)
            .bind(&req.email)
            .bind(usid)
            .bind(password_hash)
            .execute(&mut tx)
            .await;
            match response {
                Ok(_) => {
                    let response = sqlx::query(
                        "    
                        UPDATE useraddr 
                        SET
                        address = COALESCE(NULLIF($1, ''), address),
                        city = COALESCE(NULLIF($2, ''), city),
                        postcode = COALESCE(NULLIF($3, ''), postcode)
                        WHERE userid = $4
                        "
                    )
                        .bind(&req.address)
                        .bind(&req.city)
                        .bind(&req.postcode)
                        .bind(usid)
                        .execute(&mut tx)
                        .await;
                        match response {
                            Ok(_) => {
                                tx.commit().await.unwrap();
                                (StatusCode::OK, Json(json!({
                                    "status": "success",
                                    "message": "User updated successfully",
                                })))
                            },
                            Err(e) => match e {
                                
                                sqlx::Error::Database(e) => {
                                    tx.rollback().await.unwrap();
                                    match e.code() {
                                        Some(_cow) => (StatusCode::BAD_REQUEST, Json(json!({
                                            "status": "error",
                                            "message": e.to_string(),
                                        }))),
                                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                            "status": "error",
                                            "message": "Something went wrong"
                                        }))),
                                    }
                                }
                                _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                    "status": "error",
                                    "message": "Something went wrong"
                                }))),
                            },
                        }
                },
                Err(e) => match e {
                                
                    sqlx::Error::Database(e) => {
                        tx.rollback().await.unwrap();

                        match e.code() {
                            Some(_cow) => (StatusCode::BAD_REQUEST, Json(json!({
                                "status": "error",
                                "message": "User already exists",
                            }))),
                            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                                "status": "error",
                                "message": "Something went wrong"
                            }))),
                        }
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "status": "error",
                        "message": "Something went wrong"
                    }))),
                },}}



//Reset password route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//Reset password route ==============>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
pub async fn resetpasswordhandler (State(state): State<AppState>, req: Json<UserPassResetThree>) -> impl IntoResponse {
    let response = sqlx::query_as::<_, UserPassReset>(
        "SELECT users.usid, users.email from users
        WHERE users.email = $1")
        .bind(&req.email)
        .fetch_one(&state.database.db)
        .await;
        match response {
            Ok(user) => {
                let role_access = if user.email == "aradionovs@yahoo.com" { Role::Admin } else { Role::User };
                let access_secret = &state.passrecovertoken.passrecovertoken.as_bytes();
                let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &ClaimsAccessToken::new(user.usid, role_access),&EncodingKey::from_secret(access_secret)).unwrap();                                
                let email = Message::builder()
                .from("NoBody <radionovsarturs@gmail.com>".parse().unwrap())
                .reply_to("Yuin <aradionovs@yahoo.com>".parse().unwrap())
                .to(user.email.parse().unwrap())
                .subject("Reset Password")
                .body(format!("Click on the link to reset your password: https://toystoreldn.shuttleapp.rs/api/v1/users/resetpassword/{}", token))
                .unwrap();
            let creds = Credentials::new("radionovsarturs@gmail.com".to_string(), "ianrexsmfhshxqdz".to_string());
            let mailer = SmtpTransport::relay("smtp.gmail.com")
                .unwrap()
                .credentials(creds)
                .build();
            // Send the email
            match mailer.send(&email) {
                Ok(_) => println!("Email sent successfully!"),
                Err(e) => panic!("Could not send email: {:?}", e),
            }
                (StatusCode::OK, Json(json!({
                    "status": "success",
                    "message": "Email sent successfully",
                })))
            },
            Err(e) => match e {
                sqlx::Error::RowNotFound => (StatusCode::BAD_REQUEST, Json(json!({
                    "status": e.to_string(),
                    "message": "User not found",
                }))),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                    "status": e.to_string(),
                    "message": "Something went wrong"
                }))),
            },
        }
}

#[debug_handler]
pub async fn resetpasswordtokenhandler (State(state): State<AppState>, Path(token): Path<String>) -> impl IntoResponse {
    let authtoken = token.clone();
    let validation = Validation::new(Algorithm::HS256);
    let access_secret = &state.passrecovertoken.passrecovertoken.as_bytes();
    let access_verify = jsonwebtoken::decode::<ClaimsAccessToken>(&authtoken, &DecodingKey::from_secret(access_secret), &validation);
    match access_verify {
        Ok(token) => {
            let response = sqlx::query_as::<_, UserPassResetTwo>(
                "SELECT users.usid from users
                WHERE users.usid = $1")
                .bind(&token.claims.sub)
                .fetch_one(&state.database.db)
                .await;
                match response {
                    Ok(_)=>{(StatusCode::OK,Json(json!({"status":"success","message":"Token is valid",})))}
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                        "status": e.to_string(),
                        "message": "Something went wrong"
                    }))),
                
                }},
                    Err(e) => match e {
                        
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                            "status": e.to_string(),
                            "message": "Something went wrong"
                        }))),
                    },
                    }
                }
            