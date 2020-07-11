use lettre::message::{header, Message, MultiPart, SinglePart};
use lettre::error::{Error as EmailError};
use lettre::Mailbox;

const EMAIL_CSS: &str = "\
    p {\
      margin: 1.5em 0;\
    }\
    .title {\
      color: #f57f17;\
      font-size: 1.6em;\
      font-weight: normal;\
    }\
    .hr {\
      margin: 8px 0;\
      background-color: lightgray;\
      height: 1px;\
    }\
    .confirm-button {\
      border: 1px solid #c76713;\
      background-color: #f57f17;\
      color: white;\
      padding: 6px 12px;\
      text-decoration: none;\
      cursor: pointer;\
    }\
    .code-box-wrapper {\
      display: flex;\
      justify-content: space-around;\
    }\
    .code-box {\
      border: 1px solid gray;\
      background-color: lightgray;\
      padding: 6px 12px;\
      font-family: monospace;\
      font-size: 1.2em;\
    }\
    .info {\
      color: gray;\
      font-size: .8em;\
      margin-top: 24px;\
    }\
    .content {\
      max-width: 600px;\
      margin: 0 auto;\
    }";

pub fn register_user_email(from: Mailbox, to: Mailbox, site: &str,
                           username: &str, id: &str, code: &str) -> Result<Message, EmailError> {
    let link= format!("{}/?action=confirm-registration&id={}&code={}", site, id, code);
    Message::builder()
        .from(from)
        .to(to)
        .subject(format!("{} 是你的山楂记账验证码", code))
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::quoted_printable()
                        .header(header::ContentType("text/plain; charset=utf8".parse().unwrap()))
                        .body(format!("\
                        待完成操作：验证 山楂记账 账户\n\
                        ========================================\n\
                        @{}，你好：\n\
                        你已经注册了 山楂记账 。请验证账户，完成注册步骤。\n\
                        在浏览器中打开下方连接：\n\
                        {}\n\
                        或，输入验证码：\n\
                        {}\n\
                        \n\
                        注册成功之后，你可以在山楂记账上享受云同步等服务。\
                        同时，我们会尽全力保护您的用户隐私和数据完整。", username, link, code))
                )
                .singlepart(
                    SinglePart::quoted_printable()
                        .header(header::ContentType("text/html; charset=utf8".parse().unwrap()))
                        .body(format!("\
                        <!doctype html>\
                        <html lang=\"zh\">\
                          <head>\
                            <meta charset=\"utf-8\">\
                            <title>山楂记账</title>\
                            <style>{}</style>\
                          </head>\
                          <body>\
                            <div class=\"content\">\
                              <h1 class=\"title\">待完成操作：验证 山楂记账 账户</h1>\
                              <div class=\"hr\"></div>\
                              <p>@{}，你好：</p>\
                              <p>你已经注册了 山楂记账 。请验证账户，完成注册步骤。</p>\
                              <p>\
                                <a class=\"confirm-button\" href=\"{}\">验证账户</a>\
                              </p>\
                              <p>或，输入验证码：</p>\
                              <div class=\"code-box-wrapper\">\
                                <div class=\"code-box\">{}</div>\
                              </div>\
                              <p class=\"info\">注册成功之后，你可以在山楂记账上享受云同步等服务。\
                              同时，我们会尽全力保护您的用户隐私和数据完整。</p>\
                            </div>\
                          </body>\
                        </html>\
                        ", EMAIL_CSS, username, link, code))
                )
        )
}

pub fn update_user_email(from: Mailbox, to: Mailbox, site: &str,
                         username: &str, id: &str, code: &str) -> Result<Message, EmailError> {
    let link= format!("{}/?action=confirm-email-updating&id={}&code={}", site, id, code);
    Message::builder()
        .from(from)
        .to(to)
        .subject(format!("{} 是你的山楂记账验证码", code))
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::quoted_printable()
                        .header(header::ContentType("text/plain; charset=utf8".parse().unwrap()))
                        .body(format!("\
                        待完成操作：更改 山楂记账 账户的邮箱\n\
                        ========================================\n\
                        @{}，你好：\n\
                        你申请更改了 山楂记账 的邮箱。请验证邮箱，完成更新邮箱步骤。\n\
                        在浏览器中打开下方连接：\n\
                        {}\n\
                        或，输入验证码：\n\
                        {}\n\
                        \n\
                        我们会尽全力保护您的用户隐私和数据完整。", username, link, code))
                )
                .singlepart(
                    SinglePart::quoted_printable()
                        .header(header::ContentType("text/html; charset=utf8".parse().unwrap()))
                        .body(format!("\
                        <!doctype html>\
                        <html lang=\"zh\">\
                          <head>\
                            <meta charset=\"utf-8\">\
                            <title>山楂记账</title>\
                            <style>{}</style>\
                          </head>\
                          <body>\
                            <div class=\"content\">\
                              <h1 class=\"title\">待完成操作：更改 山楂记账 账户的邮箱</h1>\
                              <div class=\"hr\"></div>\
                              <p>@{}，你好：</p>\
                              <p>你申请更改了 山楂记账 的邮箱。请验证邮箱，完成更新邮箱步骤。</p>\
                              <p>\
                                <a class=\"confirm-button\" href=\"{}\">验证邮箱</a>\
                              </p>\
                              <p>或，输入验证码：</p>\
                              <div class=\"code-box-wrapper\">\
                                <div class=\"code-box\">{}</div>\
                              </div>\
                              <p class=\"info\">我们会尽全力保护您的用户隐私和数据完整。</p>\
                            </div>\
                          </body>\
                        </html>\
                        ", EMAIL_CSS, username, link, code))
                )
        )
}