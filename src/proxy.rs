use bytes::Bytes;
use regex::Regex;

use hyper::http::HeaderValue;
use hyper::{Client, Request, Response, Body, Uri};

use redis::{Client as RedisClient};

use crate::helpers;
use crate::Config;
use crate::cache;
use crate::metrics::INCOMING_REQUESTS;


#[derive(Clone)]
pub struct LastochkaServer {
    redis_client: RedisClient,
    config: Config,
}

impl LastochkaServer {
    pub fn new(
        redis_client: RedisClient,
        config: Config,
    ) -> Self {
        LastochkaServer {
             redis_client,
             config,
        }
    }

   
    async fn change_uri(&self, uri: Uri, host: &HeaderValue) -> Uri {
        let mut changed_uri = Uri::builder().
            scheme("http").
            authority(host.to_str().unwrap());
        
        let split: Vec<&str> = host.to_str().unwrap().split(":").collect();
        let port: u32 = split[1].trim().parse().expect("coudn't parse port");

        for s in self.config.settings.iter() {
            let s_port = match s.port {
                Some(p) => p,
                None => 0,
            };
            
            if port == s_port  {
                let s_team_ip = match s.team_ip.clone() {
                    Some(ip) => ip,
                    None => split[0].to_string(),
                };

                changed_uri = changed_uri.authority(s_team_ip+":"+split[1]);
            }
        }

        let path = uri.path_and_query().unwrap().as_str(); 
        let re = Regex::new("[A-Za-z0-9]{31}=").unwrap();
        
        if !re.captures(path).is_none() {
            println!("TO CHANGE URI:  {:?}", re.captures(path));

            // TODO: add flags replacement when its more 1
            if re.captures(path).unwrap().len() == 1 {
                let flag = re.captures(path).unwrap().get(0).map_or("",|f| f.as_str());
                let new_flag = helpers::build_flag(false);
                
                let flag_from_cache = match cache::get_flag(&self.redis_client, flag.to_string()).await {
                    Ok(f) => f,
                    Err(_) => return changed_uri.
                                        path_and_query(path).
                                        build().
                                        expect("build default uri")
                };
                println!("GOT FLAG IN URI {:?}", flag_from_cache);
                
                let mut changed_path: String = "".to_string();

                if flag_from_cache == "".to_string() {
                    let _result = match cache::set_flag(&self.redis_client, flag.to_string(), new_flag.clone()).await {
                        Ok(()) => println!("ok flag - new_flag"),
                        Err(e) => println!("{:?}", e),
                    };
        
                    let _result = match cache::set_flag(&self.redis_client, new_flag.clone(), flag.to_string()).await {
                        Ok(()) => println!("ok new_flag - flag"),
                        Err(e) => println!("{:?}", e),
                    };

                    changed_path = re.replace_all(path, new_flag).to_string();
                } else {
                    changed_path = re.replace_all(path, flag_from_cache).to_string();
                }
                
                println!("CHANGED URI:  {:?}", changed_path);
                
                return changed_uri.
                            path_and_query(changed_path).
                            build().
                            expect("build new uri")
            };
        }

        changed_uri.
            path_and_query(path).
            build().
            expect("build default uri")
        }

    async fn change_request_body(&self, body_bytes: Bytes) -> Result<Body, hyper::Error> {
        let re = Regex::new("[A-Za-z0-9]{31}=").unwrap();
        if !body_bytes.is_empty(){
            let text_body = std::str::from_utf8(&body_bytes).unwrap();
            // TODO: add flag on flag replacing
            // probably do it in also url query, json;

            if !re.captures(text_body).is_none() {
                println!("TO CHANGE REQUEST BODY: {:?}", text_body);

                // TODO: add flags replacement when its more 1
                if re.captures(text_body).unwrap().len() == 1 {
                    let flag = re.captures(text_body).unwrap().get(0).map_or("",|f| f.as_str());
                    let new_flag = helpers::build_flag(false);

                    let flag_from_cache = match cache::get_flag(&self.redis_client, flag.to_string()).await {
                        Ok(f) => f,
                        Err(_) => return Ok(Body::from(body_bytes)),
                    };
                    println!("GOT REQUEST BODY FLAG {:?}", flag_from_cache);
                    
                    let mut changed_text_body: String = "".to_string();
    
                    if flag_from_cache == "".to_string() {
                        let _result = match cache::set_flag(&self.redis_client, flag.to_string(), new_flag.clone()).await {
                            Ok(()) => println!("ok flag - new_flag"),
                            Err(e) => println!("{:?}", e),
                        };
            
                        let _result = match cache::set_flag(&self.redis_client, new_flag.clone(), flag.to_string()).await {
                            Ok(()) => println!("ok new_flag - flag"),
                            Err(e) => println!("{:?}", e),
                        };

                        changed_text_body = re.replace(text_body, new_flag).to_string();
                    } else {
                        changed_text_body = re.replace(text_body, flag_from_cache).to_string();
                    }

                    return Ok(Body::from(changed_text_body.to_owned()))
                }
            }

            Ok(Body::from(body_bytes))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body_bytes: Bytes) -> Result<Body, hyper::Error> {
        let re = Regex::new("[A-Za-z0-9]{31}=").unwrap();
        if !body_bytes.is_empty(){
            let text_body = std::str::from_utf8(&body_bytes).unwrap();
            // TODO: add flag on flag replacing
            // probably do it in also url query, json;

            if !re.captures(text_body).is_none() {
                println!("TO CHANGE RESPONSE BODY: {:?}", text_body);

                // TODO: add flags replacement when its more 1
                if re.captures(text_body).unwrap().len() == 1 {
                    let flag = re.captures(text_body).unwrap().get(0).map_or("",|f| f.as_str());

                    let flag_from_cache = match cache::get_flag(&self.redis_client, flag.to_string()).await {
                        Ok(f) => f,
                        Err(_) => return Ok(Body::from(body_bytes)),
                    };
                    println!("GOT RESPONSE BODY FLAG {:?}", flag_from_cache);
                    
                    if flag_from_cache != "".to_string() {
                        let changed_text_body = re.replace(text_body, flag_from_cache).to_string();

                        return Ok(Body::from(changed_text_body.to_owned()))
                    }
                }
            }

            Ok(Body::from(body_bytes))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_request(&self, req: Request<Body>) -> Result<Request<Body>, hyper::http::Error> {
        let (parts, body) = req.into_parts();
        let new_host = parts.headers.get("host").unwrap();
        let new_uri = self.change_uri(parts.uri, new_host).await;
        let body_bytes = hyper::body::to_bytes(body).await.expect("body to bytes");
        println!("body: {:?}\n{}", body_bytes, new_uri);

        let changed_request = Request::builder().
                uri(new_uri).
                body(self.change_request_body(body_bytes).await.unwrap());

        changed_request
    }

    async fn change_response(&self, resp: Response<Body>) -> Result<Response<Body>, hyper::http::Error> {
        let (parts, body) = resp.into_parts();
        let new_body = Body::from(self.change_response_body(
                hyper::body::to_bytes(body)
                    .await.expect("body to bytes"))
                .await.unwrap());
        let mut changed_resp = Response::from_parts(parts, new_body);
        // let _res = changed_resp.headers_mut().
        //     insert("Privet", "ww".parse().unwrap()).is_none();

        Ok(changed_resp)
    }

    pub async fn do_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        INCOMING_REQUESTS.inc();

        println!("{:?}", req.uri());

        let changed_req = self.change_request(req).await.unwrap();
        let service_resp = Client::new().
            request(changed_req).await.map_err(|e| {
            eprintln!("{:?}", e);
            hyper::Error::from(e)
        });

        let resp = service_resp.unwrap();
        let changed_resp = self.change_response(resp).await.unwrap();
        
        Ok(changed_resp)  
    }
}