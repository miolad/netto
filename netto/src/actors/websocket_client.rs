use actix::{Actor, Handler, Addr, StreamHandler, AsyncContext};
use actix_web::{HttpRequest, web, HttpResponse};
use actix_web_actors::ws::{WebsocketContext, self};
use super::{EncodedUpdate, metrics_collector::MetricsCollector, ClientConnected, ClientDisconnected};

#[actix_web::get("/ws/")]
async fn ws_get(
    req: HttpRequest,
    stream: web::Payload,
    collector: web::Data<Addr<MetricsCollector>>
) -> Result<HttpResponse, actix_web::Error> {
    ws::start(WebsocketClient::new(collector.get_ref().clone()), &req, stream)
}

pub struct WebsocketClient {
    /// Addr of the `MetricsCollector` actor
    metrics_collector_addr: Addr<MetricsCollector>
}

impl WebsocketClient {
    pub fn new(metrics_collector_addr: Addr<MetricsCollector>) -> Self {
        Self {
            metrics_collector_addr
        }
    }
}

impl Actor for WebsocketClient {
    type Context = WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.metrics_collector_addr.do_send(ClientConnected {
            addr: ctx.address()
        });
    }

    fn stopped(&mut self, ctx: &mut Self::Context) {
        self.metrics_collector_addr.do_send(ClientDisconnected {
            addr: ctx.address()
        });
    }
}

impl Handler<EncodedUpdate> for WebsocketClient {
    type Result = ();

    fn handle(&mut self, msg: EncodedUpdate, ctx: &mut Self::Context) -> Self::Result {
        ctx.binary(msg.inner);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebsocketClient {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        if let Ok(ws::Message::Ping(msg)) = msg {
            ctx.pong(&msg);
        }
    }
}
