# Json11
Pentru parsarea stringurilor JSON s-a folosit biblioteca C++ json11
URL Bibilioteca: https://github.com/dropbox/json11
Am ales această bibliotecă deoarece este ușor de folosit și contine doar două fișiere ( json11.hpp și json11.cpp )
Aceasta bibliotecă nu are alte dependențe.

# Explicare funcții
Pentru realizarea acestui program s-au definit anumite funcții ajutătoare.

Funcția url_encode are ca argument un pointer către un string și returnează acel string codificat conform RFC 3986 ( Capitolul 2.1 "Percent-Encoding" ).
Funcția url_decode este folosită pentru a inversa efectele funcției url_encode.

Funcția int2str transformă o valoare de tip int în reprezentarea ascii a acesteia. 
Funcția str2uint încearcă să transforme din ascii în int strict pozitiv. Această funcție are un al doilea argument de tip pointer către bool care arată dacă 
șirul ascii conține caractere non-numerice.

Funcția convert_ctime2_http_date transformă un timestamp unix în dată HTTP.
De exemplu avem t = 1557401194 , iar convert_ctime2_http_date(t) va returna "Thu, 09 May 2019 11:26:34 GMT"

Funcția parse_cookie citește un șir de forma <cookie-name>=<cookie-value>; și apoi introduce perechi de valori într-o structura de tip map.
Ex: map<string,string> cookies; string s = "prajitura=123456789"; parse_cookie(s,&cookies);
În urma acestui cod cookies["priajitura"] va avea valoarea "123456789"

Funcția parse_http_response_headers citește un răspuns HTTP "brut" și introduce valori într-o structură map.
De exemplu avem variabilele map<string,string> headers; și string s care conține răspunsul HTTP următor:

HTTP/1.1 200 OK
Date: Mon, 27 Jul 2009 12:28:53 GMT
Server: Apache/2.2.14 (Win32)
Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT
Content-Length: 88
Content-Type: text/html
Connection: keep-alive

În urma apelului la funcția parse_http_response_headers vom avea structura map completată astfel:
headers["Date"] = "Mon, 27 Jul 2009 12:28:53 GMT";
headers["Server"] = "Apache/2.2.14 (Win32)";
headers["Last-Modified"] = "Wed, 22 Jul 2009 19:15:56 GMT";
...
etc


Funcția get_hostname_from_url extrage numele hostului dintr-un URL
Ex: string s = get_hostname_from_url("google.com/search?q=123"); s va conține "google.com"

Funcția get_path_from_url extrage calea dintr-un URL
Ex: string s = get_path_from_url("google.com/search?q=123"); s va conține "/search?q=123"

Funcția server_connect returnează un socket conectat la gazda și portul specificate în argumentele funcției.
Socketul returnat de funcție are setată limită de timp atât pentru operația de scriere, cât și pentru cea de citire. 

Funcția send_all trimite tot conținutul unui șir printr-un socket.
Această funcție lucrează prin apelarea repetată a funcției send.

Funcția recv_headers citește dintr-un socket până când se întâlnește secvența "\r\n\r\n" care semnifică sfârșitul părții care
conține headerele HTTP.

Funcția recv_body citește dintr-un socket până când răspunsul HTTP este complet.

Funcția generate_http_request generează o cerere HTTP în funcție de conținutul structurii argument.
Această are ca argument un pointer către o structură de tip http_request definită în program.

Structura http_request conține toate datele necesare pentru a genera o cerere HTTP, și anume:
 - metoda (HTTP_METHOD_POST sau HTTP_METHOD_GET)
 - cale ( URI_path )
 - pereche de valori <string,string> pentru argumentele tip formular GET (URI_query)
 - pereche de valori <string,string> pentru module cookie (COOKIES)
 - pereche de valori <string,string> pentru argumentele tip formular POST (POST_query)

Această funcție este foarte "adaptivă", rezulatul putând să difere foarte mult în funcție de conținutul structurii.
Pentru cerere tip HTTP_METHOD_POST headerul "Content-Length" este calculat dinamic.
Dacă cererea este de tip HTTP_METHOD_GET, conțnutul structurii POST_query nu va fi considerat.
În cazul în care cererea este de tip POST, iar headerul "Content-Type" este egal cu "application/json", atunci corpul cererii HTTP
va fi egal cu POST_query["raw_JSON"], nemaifiind utilizat algoritmul prin care s-ar fi generat ceva 
asemănător cu raw_JSON=url_encode(&POST_query["raw_JSON"])&alt_parametru=valoare1&etc


# Algoritmul propriu-zis

Prima dată se crează conexiune cu serverul specificat în cerințele de rezolvare.
Apoi se inițializează anumite variabile folosite in program precum client_req care este structura folosită pentru a genera cereri HTTP, buffer care 
este o zonă de memorie intermediată folosită pentru a stoca datele citite din socket, response_headers care va conține headerele răspunsului etc.

Algoritmul funcționează într-o buclă while cu 5 repetări ( câte una pt fiecare etapă ).
Există cod specific pentru etapa 2 ( răspunsul la ghicitori ) și pentru ultima etapă.

Structura client_req își păstrează anumite valori în timplul repetărilor, în special headerele rămân neschimbate cu mici excepții.
Adică dacă a fost setat o singură dată headerul "Authentication" acesta își păstrează valoarea. Desigur dacă serverul 
ar trimite răspuns data["token"] = valoare_noua algoritmul ar actualiza headerul "Authentication".

Se înceracă folosirea unei conexiuni persistente, dar dacă serverul impletentat de dvs. nu ar suporta această funcție, algoritmul va rămâne funcțional.

La ultima etapă, se creează separat o conexiune cu serverul openweather.
Apoi se construiește o structură de tip http_request nouă numită openweather_req plecând de la client_req.
Se șterg modulele cookie din openweather_req și se specifică headerul "Connection" = "close" pentru a închide socketul în urma primirii răspunsului.
Răspunsul de la openwheater este stocat în variabila data_field["raw_JSON"] care mai târziu va deveni client_req.POST_query["raw_JSON"].

