use axum::{
    middleware::Next,
    http::Request,
    response::Response,
    extract::State,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{Algorithm, Validation, DecodingKey};
use crate::{customerrors::CustomErrors, AppState};
use jsonwebtoken::errors::ErrorKind;


#[derive(PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role { pub fn from_str(role: &str) -> Role {
    match role { 
        "Admin" =>  
                Role::Admin, 
        _ =>    Role::User, 
    }}}

    impl fmt::Display for Role {fn fmt(&self, f: &mut fmt::Formatter<'_>) ->
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
    pub fn _new (id: Uuid, role: Role ) -> Self { 
    let iat = Utc::now();
    let exp = iat + Duration::hours(1);
    Self {
        sub: id,
        iat: iat.timestamp(),
        exp: exp.timestamp(),
        role: role.to_string(),
}}}



pub async fn auth_middleware<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, CustomErrors> 
where
    B: Send,
    {
        request.headers().get("Authorization").ok_or(CustomErrors::NotLoggedIn)?;
        let auth =request.headers().get("Authorization").ok_or(CustomErrors::MissingCreds)?;
        let token = auth.to_str().map_err(|_| CustomErrors::MissingCreds)?;
        let authtoken = token.replace("Bearer ", "");
        let validation = Validation::new(Algorithm::HS256);
        let access_token_secret: String = state.accesstoken.accesstoken.clone();
        let access_secret = &access_token_secret.as_bytes();
        let access_verify = jsonwebtoken::decode::<ClaimsAccessToken>(&authtoken, &DecodingKey::from_secret(access_secret), &validation);
        match access_verify {
            Ok(_) => 
                Ok(next.run(request).await),
            Err(e) => {
                println!("access_verify: {:?}", e);
                match e.kind() {
                    ErrorKind::InvalidToken => {
                        println!("access_verify: {:?}", e);
                        Err(CustomErrors::InvalidToken)
                    }
                    _ => {
                        println!("access_verify: {:?}", e);
                        Err(CustomErrors::InvalidKey)
        }}}}}


        pub async fn admin_auth_middleware<B>(
            State(state): State<AppState>,
            request: Request<B>,
            next: Next<B>,
        ) -> Result<Response, CustomErrors>
        where
            B: Send,
        {
            request.headers().get("Authorization").ok_or(CustomErrors::NotLoggedIn)?;
            let auth =request.headers().get("Authorization").ok_or(CustomErrors::MissingCreds)?;
            let token = auth.to_str().map_err(|_| CustomErrors::MissingCreds)?;
            let authtoken = token.replace("Bearer ", "");
            let validation = Validation::new(Algorithm::HS256);
            let access_token_secret: String = state.accesstoken.accesstoken.clone();
            let access_secret = &access_token_secret.as_bytes();
            let access_verify = jsonwebtoken::decode::<ClaimsAccessToken>(&authtoken, &DecodingKey::from_secret(access_secret), &validation);
            match access_verify {
                Ok(claims) => {
                    let role = Role::from_str(&claims.claims.role);
                    
                    if role == Role::Admin {
                        Ok(next.run(request).await)
                    } else {
                        Err(CustomErrors::NotAuthorized)
                    }
                }
                Err(e) => {
                    println!("access_verify: {:?}", e);
                    match e.kind() {
                        ErrorKind::InvalidToken => {
                            println!("access_verify: {:?}", e);
                            Err(CustomErrors::InvalidToken)
                        }
                        _ => {
                            println!("access_verify: {:?}", e);
                            Err(CustomErrors::InvalidKey)
            }}}}}


