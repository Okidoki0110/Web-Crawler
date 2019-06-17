#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <ctime>
#include <ctgmath>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "json11.hpp"

#define HTTP_METHOD_UNDEFINED 0
#define HTTP_METHOD_GET 1
#define HTTP_METHOD_POST 2
#define HTTP_METHOD_HEAD 3
#define HTTP_METHOD_PUT 4
#define HTTP_METHOD_DELETE 5

#define server_ip "185.118.200.35"
#define server_port 8081

struct http_request {
    int request_method;
    std::unordered_map <std::string , std::string> request_headers;
    std::string URI_path;
    std::unordered_map <std::string,std::string> URI_query;
    std::unordered_map <std::string,std::string> COOKIES;
    std::unordered_map <std::string,std::string> POST_query;
};


// pentru transformare din int in string
std::string int2str(int n,uint8_t base = 10) {
    std::string result;
    const char* base_charset="0123456789abcdef";

    if(n == 0) {
        result="0";
    }
    bool sign = false;

    if(n < 0) {
        n*=-1; sign = true;
    }

    while(n != 0) {
        char c = base_charset[n % base];
        n/=base;
        result.insert(0,1,c);
    }
 
    if(sign) {
        result.insert(0,1,'-');
    }

    return result;
}

// pentru transformare din ascii in int
unsigned int str2uint(const std::string *str,bool *invalid_chars) {
    unsigned int result=0;
    std::string number=str[0];

    while(number.size() != 0) {
        char digit=number[0];
        if(digit < '0' or digit > '9') {
            if(invalid_chars != 0) {
                invalid_chars[0]=true;
            } 
            return 0;
        }
        result+=(int(digit - '0')) * pow(10,number.size()-1);
        number.erase(0,1);
    }

    if(invalid_chars != 0){
        invalid_chars[0]=false;
    }
    return result;
}

// pentru a genera data in format HTTP
std::string convert_ctime2_http_date(time_t t) {
    struct tm* time_struct = gmtime(&t);
    char buffer[30];
    std::string result;
    strftime(buffer,30,"%a, %d %b %Y %H:%M:%S ",time_struct);
    result = buffer;
    result.append("GMT");

    return result;
}

// pentru a codifica semnele speciale
std::string url_encode(const std::string* s) {
    std::string result;
    const char* hex_charset = "0123456789ABCDEF";
    for(size_t i=0; i<s->size(); i++) {
    if(s[0][i] >= 'A' and s[0][i] <= 'Z'){
        result.append(1,s[0][i]);
    }
    else 
        if(s[0][i] >= 'a' and s[0][i] <= 'z'){
            result.append(1,s[0][i]);
        }
        else
             if(s[0][i] >= '0' and s[0][i] <= '9'){
                result.append(1,s[0][i]);
            }
            else 
                if(s[0][i] == '_' or s[0][i] == '-' or s[0][i] == '.' or s[0][i] == '~'){
                    result.append(1,s[0][i]);
                }
                else {
                        result.append(1,'%');
                        result.append(1,hex_charset[(s[0][i] >> 4 ) & 0x0f]);
                        result.append(1,hex_charset[s[0][i] & 0x0f]);
                    }

        }

        return result;
}

// pentru a decodifica semnele speciale
bool url_decode(const std::string* s,std::string* result) {
    std::string hex_charset = "0123456789ABCDEF";
    std::string hex_charset_low = "0123456789abcdef";
    result->clear();
    for(size_t i=0; i<s->size(); i++) {
        if(s[0][i] >= 'A' and s[0][i] <= 'Z'){
            result->append(1,s[0][i]);
        }
        else 
            if(s[0][i] >= 'a' and s[0][i] <= 'z') {
                result->append(1,s[0][i]);
            }
            else 
                if(s[0][i] >= '0' and s[0][i] <= '9') {
                    result->append(1,s[0][i]);
                }
                else 
                    if(s[0][i] == '_' or s[0][i] == '-' or s[0][i] == '.' or s[0][i] == '~'){
                        result->append(1,s[0][i]);
                    }
                    else 
                        if(s[0][i] == '%')  {
                            if(i + 2 > s->size()) {
                                result->clear(); 
                                return false;
                            } 
                            size_t high_half_pos = hex_charset.find(s[0][i + 1]);
                            if(high_half_pos == std::string::npos) {
                                high_half_pos = hex_charset_low.find(s[0][i + 1]);
                                if(high_half_pos == std::string::npos) {
                                    result->clear();
                                     return false;
                                }
                            }

                            size_t low_half_pos = hex_charset.find(s[0][i + 2]);
                            if(low_half_pos == std::string::npos) {
                                    low_half_pos = hex_charset_low.find(s[0][i + 2]);
                                    if(low_half_pos == std::string::npos) {
                                        result->clear();
                                        return false;
                                    }
                                }
                            char c = (char)( low_half_pos | ( high_half_pos << 4) );
                            result->append(1,c);
                            i+=2;
                        }

                        else {
                        result->clear(); 
                        return false;
                        }

        }
        return true;
}

// parsarea URI
bool parse_http_URI(const std::string* raw_request,std::string* URI,std::unordered_map<std::string , std::string>* URI_query_params) {
    size_t new_line_position = raw_request->find("\r\n");
    // 20kb request first line
    if(new_line_position == std::string::npos or new_line_position > 1024 * 20) {
        return false;
    }
    size_t first_space_separator = raw_request->find(' ');
    if(first_space_separator == std::string::npos or first_space_separator > new_line_position) {
        return false;
    }
    size_t second_space_separator = raw_request->find(' ',first_space_separator+1);
    if(second_space_separator == std::string::npos or second_space_separator > new_line_position) {
        return false;
    }
    std::string full_URI = raw_request->substr(first_space_separator+1,(second_space_separator-first_space_separator) - 1);
    if(full_URI.size() > 1024 * 20) {
        return false;} // 20kb request line
    size_t query_mark = full_URI.find('?');
    if(query_mark == std::string::npos) {
        URI[0] = full_URI;
        return true;
    }
    URI[0] = full_URI.substr(0,query_mark);
    std::string query_part = full_URI.substr(query_mark+1);
    std::string query_name,query_value,dec_query_name,dec_query_value;
    size_t query_current_position = 0;
    while(true) {
        size_t query_def_sign = query_part.find('=',query_current_position);
        if(query_def_sign == std::string::npos) {
            break;
        }
        query_name = query_part.substr(query_current_position,query_def_sign - query_current_position);
        if(!url_decode(&query_name,&dec_query_name)) {
            return false;
        }
        query_name.clear();
        size_t query_and_sign = query_part.find('&',query_def_sign);
        if(query_and_sign == std::string::npos) {
            query_value = query_part.substr(query_def_sign+1); 
            if(!url_decode(&query_value,&dec_query_value)) {
                return false;
            }
            query_value.clear();
            URI_query_params[0][dec_query_name] = dec_query_value; 
            break;
        }

        query_value = query_part.substr(query_def_sign+1,(query_and_sign - query_def_sign)-1);
        if(!url_decode(&query_value,&dec_query_value)) {
            return false;
        }
        query_value.clear();
        URI_query_params[0][dec_query_name] = dec_query_value;
        query_current_position = query_and_sign + 1; 
    }
    return true;
}

 // parsarea modulelor cookie
bool parse_cookie(std::string cookie,std::unordered_map<std::string , std::string>* cookies) {
    if(cookie.find(";") != std::string::npos) {
        cookie=cookie.substr(0,cookie.find(";"));
    }
    size_t def_sign_pos = cookie.find("=");
    if(def_sign_pos == std::string::npos) {
        return false;
    }
    std::string cookie_name = cookie.substr(0,def_sign_pos);
    std::string cookie_value = cookie.substr(def_sign_pos+1);
    if(cookie_name.size() > 0) {
        cookies[0][cookie_name]=cookie_value;
    }
    return true;
}

// parsarea headerelor + cookies
bool parse_http_response_headers(const std::string* raw_request,std::unordered_map<std::string , std::string>* request_headers,std::unordered_map<std::string , std::string>* cookies) {
    size_t start_position = raw_request->find("\r\n");
    if(start_position == std::string::npos) {
        return false;
    }
    start_position+=2;
    size_t stop_position = raw_request->find("\r\n\r\n");
    if(stop_position == std::string::npos) {
        return false;
    }
    std::string header_name,header_value;
    while(true) {
        if(start_position >= raw_request->size() 
                or (raw_request[0][start_position] == '\r'
                    and raw_request[0][start_position + 1] == '\n')) {
                        break;
        }

        size_t point_position = raw_request->find(": ",start_position);
        if(point_position == std::string::npos) {
            return false;
        }
        header_name = raw_request->substr(start_position,point_position - start_position);
        size_t new_line_position = raw_request->find("\r\n",point_position);
        if(new_line_position == std::string::npos) {
            return false;
        }
        header_value = raw_request->substr(point_position + 2,new_line_position - (point_position + 2));
        if(header_value.find('\r') != std::string::npos or header_value.find('\n') != std::string::npos) {
            return false;
        }
        request_headers[0][header_name] = header_value;
        if(header_name == "Set-Cookie" or header_name == "set-cookie") {
            if(!parse_cookie(header_value,cookies)) {
                return false;
            }
        }
        start_position = new_line_position + 2;
    }
    return true;
}

// generarea unei cereri http 
std::string generate_http_request(struct http_request* client_req) {
    std::string result;
    if(client_req->request_method == HTTP_METHOD_GET) {
        result = "GET ";
    } 
    else {
        result = "POST ";
    }
    result.append(client_req->URI_path);
    if(!client_req->URI_query.empty()) {
        result.append("?");
        for(auto i = client_req->URI_query.begin(); i != client_req->URI_query.end(); ++i) {
            result.append(url_encode(&i->first));
            if(i->second.size() > 0) {
                result.append("=");
                result.append(url_encode(&i->second));
            }
            result.append("&");
        }

        result.pop_back();

    }

    result.append(" HTTP/1.1\r\n");
    std::string post_body;
    if(client_req->request_method == HTTP_METHOD_POST) {
        if(client_req->request_headers["Content-Type"] == "application/x-www-form-urlencoded") {
            for(auto i = client_req->POST_query.begin(); i != client_req->POST_query.end(); ++i) {
                post_body.append(url_encode(&i->first));
                if(i->second.size() > 0) {
                    post_body.append("="); post_body.append(url_encode(&i->second));
                }
                post_body.append("&");
            }

            if(post_body.size() > 0) {
                post_body.pop_back();
            };
    }
    else {
        post_body = client_req->POST_query["raw_JSON"];
    }
    client_req->request_headers["Content-Length"] = int2str(post_body.size());
    }
    if(!client_req->COOKIES.empty()) {
        std::string cookie_header_value;
        for(auto i=client_req->COOKIES.begin(); i!=client_req->COOKIES.end(); ++i) {
            cookie_header_value.append(i->first); cookie_header_value.append("=");
            cookie_header_value.append(i->second); cookie_header_value.append("; ");
            }
        cookie_header_value.pop_back();
        cookie_header_value.pop_back();
        client_req->request_headers["Cookie"] = cookie_header_value;
    }
    for(auto i=client_req->request_headers.begin(); i != client_req->request_headers.end(); ++i) {
        result.append(i->first); result.append(": ");
        result.append(i->second); result.append("\r\n");
    }
    result.append("\r\n");
    if(client_req->request_method == HTTP_METHOD_POST) {
        result.append(post_body);
    }
    return result;
}


std::string get_hostname_from_url(std::string full_url) {
    return full_url.substr(0,full_url.find("/"));
}

std::string get_path_from_url(std::string full_url) {
    return full_url.substr(full_url.find("/"));
}

int server_connect(const char* hostname,uint16_t port) {
    int s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s == -1) {
        std::cout << "Nu se poate creea socketul TCP!" << std::endl;
        exit(-1);
    }
    struct sockaddr_in tcp_addr;
    memset(&tcp_addr,0,sizeof(struct sockaddr_in));
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(port); 
    struct hostent* resolved_host = gethostbyname2(hostname,AF_INET); // pentru adrese ipv4
    if(resolved_host == NULL) {
        std::cout << "Nu se poate gasi adresa ip pentru hostname!" << std::endl;
        exit(-1);
    }
    memcpy(&tcp_addr.sin_addr,resolved_host->h_addr,4);
    struct timeval timeout;      
    timeout.tv_sec = 15;
    timeout.tv_usec = 0;
    if(setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(struct timeval)) == -1) {
        std::cout << "Nu se poate pune limita de timp pt operatia de citire din socket!" << std::endl;
        exit(-1);
    }
    if(setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(struct timeval)) == -1) {
        std::cout << "Nu se poate pune limita de timp pt operatia de scriere din socket!" << std::endl;
        exit(-1);
    }
    if(connect(s,(struct sockaddr*)&tcp_addr,sizeof(struct sockaddr_in)) == -1) {
        std::cout << "Conexiunea cu serverul nu poate fi realizata!" << std::endl;
        exit(-1);
    } 
        return s;
}

void send_all(int s,const std::string* buffer) {
    size_t send_bytes = 0;
    while(true) {
        int r = send(s,buffer->c_str() + send_bytes,buffer->size() - send_bytes,0);
        if(r < 0) {
            if(errno == ETIMEDOUT) {
                std::cout << "Conexiunea cu serverul a expirat din cauza limitei de timp!" << std::endl;
                exit(0);
            }
            std::cout << "Functia send a dat eroare!" << std::endl;
            exit(-1);
        }

        send_bytes+=r;
        if(send_bytes == buffer->size()) {
            break;
        }
    }
}

void recv_headers(int s,char* buffer,size_t buffer_size,std::string *raw_response) {
    while(true) {
        int r = recv(s,buffer,buffer_size,0);
        if(r < 0) {
            if(errno == ETIMEDOUT) {
                std::cout << "Conexiunea cu serverul a expirat din cauza limitei de timp!" << std::endl; 
                exit(0);
            }
            std::cout << "Functia recv a dat eroare!" << std::endl;
            exit(-1);
        }
        raw_response->append(buffer,r);
        if(raw_response->find("\r\n\r\n") != std::string::npos) // headerele au fost trimise complet 
            {break;}
    }
} 

void recv_body(int s,char* buffer,size_t buffer_size,__uint64_t content_length,std::string *raw_response) {
    size_t calculated_http_response_len = raw_response->find("\r\n\r\n") + 4 + content_length;
    // citire corp raspuns (body)
    while(true) {
        if(calculated_http_response_len == raw_response->size()) {
            break;   // raspunsul serverului este complet
        }
        int r = recv(s,buffer,buffer_size,0);
        if(r < 0) {
            if(errno == ETIMEDOUT) {
                std::cout << "Conexiunea cu serverul a expirat din cauza limitei de timp!" << std::endl;
                exit(0);
            }
            std::cout << "Functia recv a dat eroare!" << std::endl;
            exit(-1);
        }
        raw_response->append(buffer,r);

    }
}

int main() {
    int http_client_socket = server_connect(server_ip,server_port);
    char buffer[1204 * 60];
    std::string raw_http_request,raw_http_response;
    int send_bytes;
    std::unordered_map<std::string,std::string> response_header;
    struct http_request client_req;
    client_req.request_method = HTTP_METHOD_GET;
    client_req.URI_path = "/task1/start";
    client_req.request_headers["Host"] = server_ip;
    client_req.request_headers["User-Agent"] = "REST_PARSER 0.1";
    client_req.request_headers["Connection"] = "keep-alive";

    int etapa = 1;
    while(etapa != 6) {
        client_req.request_headers["Date"] = convert_ctime2_http_date(time(NULL));
        raw_http_request = generate_http_request(&client_req);
        send_all(http_client_socket,&raw_http_request);
        raw_http_response.clear();
        recv_headers(http_client_socket,buffer,sizeof(buffer),&raw_http_response);
        response_header.clear();
        if(!parse_http_response_headers(&raw_http_response,&response_header,&client_req.COOKIES)) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }
        std::string response_body_size_ascii; 
        if(response_header.find(std::string("Content-Length")) == response_header.end()) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }
        else {
            response_body_size_ascii = response_header["Content-Length"];
        }
        bool is_bad_num = true;
        size_t response_body_size=str2uint(&response_body_size_ascii,&is_bad_num);
        if(is_bad_num) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }

        recv_body(http_client_socket,buffer,sizeof(buffer),response_body_size,&raw_http_response);
        std::string JSON_body = raw_http_response.substr(raw_http_response.find("\r\n\r\n") + 4);
        std::unordered_map<std::string,std::string> data_field;
        std::string JSON_error;
        auto JSON_decoded_object = json11::Json::parse(JSON_body,JSON_error);
        auto JSON_object = JSON_decoded_object.object_items();
        if(JSON_error.size() > 0) {
            std::cout << JSON_body << std::endl;
            if(etapa == 5) {
                return 0;
            } // am facut totul bine
        std::cout << "Eroare la cererea cu numarul "<< etapa << std::endl;
        std::cout << "Alta data il fac mai bine :)" << std::endl;
        return -1;
        }

        if(JSON_object.find("url") == JSON_object.end()) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }

        if(JSON_object.find("method") == JSON_object.end()) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }

        if(JSON_object.find("enunt") != JSON_object.end()) {
            std::cout << std::endl << JSON_object["enunt"].string_value() << std::endl << std::endl;
        }
        if(JSON_object.find("data") != JSON_object.end()) {
            auto JSON_data_field_decoded = json11::Json::parse(JSON_object["data"].dump(),JSON_error);
            auto JSON_data_field = JSON_data_field_decoded.object_items();
            for(auto i = JSON_data_field.begin(); i != JSON_data_field.end(); ++i) {
                data_field[i->first] = i->second.string_value();
                if(i->first == "token") {
                    client_req.request_headers["Authorization"] = "Bearer "; 
                    client_req.request_headers["Authorization"].append(i->second.string_value());
                    data_field.erase("token");
                }
            }
            if(data_field.find("queryParams") != data_field.end()) {
                auto GET_query_decoded = json11::Json::parse(JSON_data_field["queryParams"].dump(),JSON_error);
                auto GET_query_field = GET_query_decoded.object_items();
                for(auto i = GET_query_field.begin(); i != GET_query_field.end(); ++i) {
                    data_field[i->first] = i->second.string_value();
                }
                data_field.erase("queryParams");
            }

        }
        // cod specific pentru etape

        if(etapa == 2) {// chestia cu ce merge in patru picioare :))
            data_field["raspuns1"] = "Omul";
            data_field["raspuns2"] = "Numele";
        }
        if(etapa == 4) // pentru cererea http la api.openweathermap.org
        {
            int openweather_socket = server_connect(get_hostname_from_url(data_field["url"]).c_str(),80); 
            struct http_request openweather_req = client_req;
            openweather_req.request_method = (data_field["method"] == "GET") ? HTTP_METHOD_GET : HTTP_METHOD_POST;
            openweather_req.request_headers["Host"] = get_hostname_from_url(data_field["url"]);
            openweather_req.request_headers["Connection"] = "close";
            openweather_req.URI_path = get_path_from_url(data_field["url"]);
            openweather_req.COOKIES.clear();
            openweather_req.request_headers.erase("Cookie");
            data_field.erase("url");
            data_field.erase("method");
            openweather_req.URI_query = data_field;
            std::string openweather_request = generate_http_request(&openweather_req);
            send_all(openweather_socket,&openweather_request);
            raw_http_response.clear();
            recv_headers(openweather_socket,buffer,sizeof(buffer),&raw_http_response);
            response_header.clear();
            if(!parse_http_response_headers(&raw_http_response,&response_header,&openweather_req.COOKIES)) {
                std::cout << "Raspuns malformat de la server!" << std::endl;
                return -1;
            }
            if(response_header.find(std::string("Content-Length")) == response_header.end()) {
                std::cout << "Raspuns malformat de la server!" << std::endl;
                return -1;
            }
            else {
                response_body_size_ascii = response_header["Content-Length"];
            }
            is_bad_num = true;
            response_body_size=str2uint(&response_body_size_ascii,&is_bad_num);
            if(is_bad_num) {
                std::cout << "Raspuns malformat de la server!" << std::endl;
                return -1;
            }
            recv_body(openweather_socket,buffer,sizeof(buffer),response_body_size,&raw_http_response);
            data_field.clear();
            data_field["raw_JSON"] = raw_http_response.substr(raw_http_response.find("\r\n\r\n") + 4);
            close(openweather_socket);
            client_req.URI_query.clear();
            client_req.request_headers["Connection"] = "Close";
        }
        if(JSON_object["method"].string_value() == "POST") {
            if(JSON_object.find("type") == JSON_object.end()) {
            std::cout << "Raspuns malformat de la server!" << std::endl;
            return -1;
        }

            client_req.request_headers["Content-Type"] = JSON_object["type"].string_value();
            client_req.POST_query = data_field;
            client_req.request_method = HTTP_METHOD_POST;
        }
        else 
            if(JSON_object["method"].string_value() == "GET") {
                client_req.request_method = HTTP_METHOD_GET;
                client_req.URI_query = data_field;
                auto content_type_header_i = client_req.request_headers.find("Content-Type");
                if(content_type_header_i != client_req.request_headers.end()) {
                    client_req.request_headers.erase(content_type_header_i);
                }
                auto content_len_header_i = client_req.request_headers.find("Content-Length");
                if(content_len_header_i != client_req.request_headers.end()) {
                    client_req.request_headers.erase(content_len_header_i);
                }
            }
            else {
                std::cout << "Raspuns malformat de la server!" << std::endl;
                return -1;
            }

            client_req.URI_path = JSON_object["url"].string_value();
            if(response_header.find("Connection") == response_header.end()) {
                std::cout << "Raspuns malformat de la server!" << std::endl;
                return -1;
            }   
            if(response_header["Connection"] != "keep-alive" and response_header["Connection"] != "Keep-Alive") {
                close(http_client_socket);  
                http_client_socket = server_connect(server_ip,server_port);
            }
            etapa++;
        }
    close(http_client_socket);
    return 0;
}
