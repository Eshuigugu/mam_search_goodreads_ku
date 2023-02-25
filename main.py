import datetime
import hashlib
import hmac
import http.client
import time
from time import sleep
import requests
import json
from bs4 import BeautifulSoup
import os
import pickle
from appdirs import user_data_dir
import re

# this script does create some files under this directory
appname = "search_goodreads"
appauthor = "Eshuigugu"
data_dir = user_data_dir(appname, appauthor)
lang_code_to_name = {'ENG': 'English'}

if not os.path.isdir(data_dir):
    os.makedirs(data_dir)
sess_filepath = os.path.join(data_dir, 'session.pkl')

mam_blacklist_filepath = os.path.join(data_dir, 'blacklisted_ids.txt')
if os.path.exists(mam_blacklist_filepath):
    with open(mam_blacklist_filepath, 'r') as f:
        blacklist = set([int(x.strip()) for x in f.readlines()])
else:
    blacklist = set()

if os.path.exists(sess_filepath):
    sess = pickle.load(open(sess_filepath, 'rb'))
    # only take the cookies
    cookies = sess.cookies
    sess = requests.Session()
    sess.cookies = cookies
else:
    sess = requests.Session()


# The payload to include in the request (the GraphQL query)
def book_by_id_query(book_id: str):
    query = {"operationName": "getBookByLegacyId", "variables": {
        "legacyBookId": book_id
    }, 'query': '''
query getBookByLegacyId($legacyBookId: Int!, $rto: String) {
  getBookByLegacyId(legacyId: $legacyBookId) {
    title
    titleComplete
    legacyId
    webUrl
    details {
      ...BookPageDetails
      __typename
    }
    links(rto: $rto) {
      primaryAffiliateLink {
        ... on KindleLink {
          url
          ref
          ebookPrice
          kuEligible
          primeEligible
        }
      }
    }
  }
}

fragment BookPageDetails on BookDetails {
  language {
    name
    __typename
  }
  __typename
}
'''}
    return query


def list_book_suggestions_query(search_query: str):
    query = {
        "operationName": "getSearchSuggestions",
        "variables": {
            "searchQuery": search_query
        },
        "query": "query getSearchSuggestions($searchQuery: String!) {\n  getSearchSuggestions(query: $searchQuery) {\n    edges {\n      ... on SearchBookEdge {\n        node {\n          id\n          title\n          primaryContributorEdge {\n            node {\n              name\n              isGrAuthor\n              __typename\n            }\n            __typename\n          }\n          webUrl\n          imageUrl\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
    }
    return query


class GoodreadsGraphQL:
    def __init__(self):
        self.credentials_expiration_timestamp = 0
        self.access_key_id = None
        self.secret_access_key = None
        self.security_token = None
        # The GraphQL endpoint URL
        self.graphql_url = 'https://kxbwmqov6jgg3daaamb744ycu4.appsync-api.us-east-1.amazonaws.com/graphql'
        self.conn = http.client.HTTPSConnection("kxbwmqov6jgg3daaamb744ycu4.appsync-api.us-east-1.amazonaws.com")

    def get_auth(self):
        if time.time() >= self.credentials_expiration_timestamp:
            session = requests.Session()
            session.headers = {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}

            # get IdentityId from aws using hardcoded IdentityPoolId
            data = json.dumps({"IdentityPoolId": "us-east-1:16da77fa-4392-4d35-bd47-bb0e2d3f73be"})
            headers = {
                'authority': 'cognito-identity.us-east-1.amazonaws.com',
                'accept': '*/*',
                'content-type': 'application/x-amz-json-1.1',
                'x-amz-target': 'AWSCognitoIdentityService.GetId',
                'x-amz-user-agent': 'aws-sdk-js/2.711.0 callback',
            }
            response = session.post('https://cognito-identity.us-east-1.amazonaws.com/', headers=headers, data=data)
            response_json = response.json()

            data = json.dumps({"IdentityId": response_json['IdentityId']})
            headers = {
                'authority': 'cognito-identity.us-east-1.amazonaws.com',
                'accept': '*/*',
                'content-type': 'application/x-amz-json-1.1',
                'x-amz-target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
                'x-amz-user-agent': 'aws-sdk-js/2.711.0 callback',
            }
            response = session.post('https://cognito-identity.us-east-1.amazonaws.com/', headers=headers, data=data)
            response_json = response.json()
            if 'Credentials' not in response_json:
                print('bad response', response_json)
            # these credentials expire after an hour
            self.access_key_id = response_json['Credentials']['AccessKeyId']
            self.secret_access_key = response_json['Credentials']['SecretKey']
            self.security_token = response_json['Credentials']['SessionToken']
            self.credentials_expiration_timestamp = response_json['Credentials']['Expiration']
        return self.access_key_id, self.secret_access_key, self.security_token

    def query_graphql(self, query: dict):
        access_key_id, secret_access_key, security_token = self.get_auth()
        # The current date in the AWS ISO 8601 format (YYYYMMDD'T'HHMMSS'Z')
        amz_date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

        # The headers to include in the request
        headers = {
            'content-type': 'application/json; charset=UTF-8',
            'x-amz-security-token': self.security_token,
            'x-amz-date': amz_date,
            'host': 'kxbwmqov6jgg3daaamb744ycu4.appsync-api.us-east-1.amazonaws.com',
            'accept': '*/*',
        }
        # The headers to sign with the AWS secret access key
        signed_headers = ';'.join(sorted(list(headers.keys())))

        payload = json.dumps(query)

        # The canonical request string to sign
        canonical_request = '\n'.join([
            'POST',
            '/graphql',
            '',
            *map(lambda x: ":".join(x), sorted(headers.items(), key=lambda x: x[0])),
            '',
            signed_headers,
            hashlib.sha256(payload.encode('utf-8')).hexdigest()
        ]).strip()

        aws_region = 'us-east-1'
        aws_service = 'appsync'

        def hash_query():
            date_stamp = amz_date[:8]

            # Define the string to sign
            string_to_sign = 'AWS4-HMAC-SHA256\n' + amz_date + '\n' + date_stamp + '/' + aws_region + '/' + aws_service + '/aws4_request\n' + hashlib.sha256(
                canonical_request.encode('utf-8')).hexdigest()
            # Define the signing key
            kDate = hmac.new(('AWS4' + secret_access_key).encode('utf-8'), date_stamp.encode('utf-8'),
                             hashlib.sha256).digest()
            kRegion = hmac.new(kDate, aws_region.encode('utf-8'), hashlib.sha256).digest()
            kService = hmac.new(kRegion, aws_service.encode('utf-8'), hashlib.sha256).digest()
            kSigning = hmac.new(kService, b'aws4_request', hashlib.sha256).digest()

            # Define the signature
            signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
            return signature

        signature = hash_query()

        authorization_header = f'AWS4-HMAC-SHA256 Credential={access_key_id}/{amz_date[:8]}/us-east-1/appsync/aws4_request, SignedHeaders={signed_headers}, Signature={signature}'

        session = requests.Session()
        session.headers = {}

        headers = {'Authorization': authorization_header} | headers
        conn = self.conn
        conn.request("POST", "/graphql", payload, headers)
        res = conn.getresponse()
        data = res.read()
        sleep(1)  # be nice to Goodreads
        try:
            return json.loads(data.decode("utf-8"))['data']
        except:
            print('error', data)
            time.sleep(30)
            return self.query_graphql(query)



def parse_series_position(series_positions):
    if ',' in series_positions:
        series_positions = series_positions.strip(',').split(',')
    elif '-' in series_positions:
        series_start, series_end = series_positions.split('-')
        if series_start.isdigit() and series_end.isdigit():
            series_positions = list(range(int(series_start), int(series_end) + 1))
    else:
        series_positions = [series_positions]
    return series_positions


def search_goodreads(title, authors, series_name_position=None, language=None):
    # remove initials from author's name because they can mess up the search
    reduce_author = lambda name: ' '.join([x for x in name.split(' ') if len(x) > 2]) if name.count(
        ' ') > 1 else name
    authors = list(map(reduce_author, authors))
    # search by title and author
    queries = list({f'{title} {author}'
                    for author in authors[:5]})
    if series_name_position:
        # also search by series and title
        queries += [f'{series_name_position[0]} {str(pos).lstrip("0")} {author}' for pos in
                    parse_series_position(series_name_position[1]) for author in authors]
    found_books = []
    for query in queries[:20]:
        search_results = \
        goodreads_graphql.query_graphql(list_book_suggestions_query(search_query=query))['getSearchSuggestions'][
            'edges']
        for book in search_results:
            book = book['node']
            goodreads_edition_id = re.search('goodreads.com/book/show/(\d+)', book['webUrl']).group(1)
            result = goodreads_graphql.query_graphql(book_by_id_query(goodreads_edition_id))['getBookByLegacyId']
            result_title = result['titleComplete']
            if language and result['details']['language']['name'] != language:  # check if language matches
                continue
            # availibility shows how you can get the books through amazon
            availability = result['links']['primaryAffiliateLink']
            if availability and (float(availability['ebookPrice']) == 0 or availability['kuEligible'] or availability['primeEligible']):
                found_books.append({'title': result_title, 'url': availability['url'], 'sort_key': len(search_results)})
    found_books = list({x['url']:x for x in found_books}.values())
    return sorted(found_books, key=lambda x: x['sort_key'])


def get_mam_requests(limit=5000):
    keepGoing = True
    start_idx = 0
    req_books = []

    # fetch list of requests to search for
    while keepGoing:
        time.sleep(1)
        url = 'https://www.myanonamouse.net/tor/json/loadRequests.php'
        headers = {}
        # fill in mam_id for first run
        # headers['cookie'] = 'mam_id='

        query_params = {
            'tor[text]': '',
            'tor[srchIn][title]': 'true',
            'tor[viewType]': 'unful',
            'tor[startDate]': '',
            'tor[endDate]': '',
            'tor[startNumber]': f'{start_idx}',
            'tor[sortType]': 'dateD'
        }
        headers['Content-type'] = 'application/json; charset=utf-8'

        r = sess.get(url, params=query_params, headers=headers, timeout=60)
        if r.status_code >= 300:
            raise Exception(f'error fetching requests. status code {r.status_code} {r.text}')

        req_books += r.json()['data']
        total_items = r.json()['found']
        start_idx += 100
        keepGoing = min(total_items, limit) > start_idx and not \
            {x['id'] for x in req_books}.intersection(blacklist)

    # saving the session lets you reuse the cookies returned by MAM which means you won't have to manually update the mam_id value as often
    with open(sess_filepath, 'wb') as f:
        pickle.dump(sess, f)

    with open(mam_blacklist_filepath, 'a') as f:
        for book in req_books:
            f.write(str(book['id']) + '\n')
            book['url'] = 'https://www.myanonamouse.net/tor/viewRequest.php/' + \
                          str(book['id'])[:-5] + '.' + str(book['id'])[-5:]
            book['title'] = BeautifulSoup(book["title"], features="lxml").text
            if book['series']:
                book['series'] = {k: [BeautifulSoup(x, features="lxml").text for x in v] for k, v in
                                  json.loads(book['series']).items()}
            if book['authors']:
                book['authors'] = [author for k, author in json.loads(book['authors']).items()]
    return req_books


def main():
    req_books = get_mam_requests()

    req_books_reduced = [x for x in req_books if
                         x['cat_name'].startswith('Ebooks ')
                         and x['filled'] == 0
                         and x['torsatch'] == 0
                         and x['category'] != 79  # remove magazines/newspapers
                         and x['id'] not in blacklist]
    for book in req_books_reduced:
        try:
            hits = search_goodreads(book['title'], book['authors'],
                                 series_name_position=list(book['series'].values())[0] if book['series'] else None,
                                 language=lang_code_to_name[book['lang_code']] if book['lang_code'] in lang_code_to_name else None)
        except:
            sleep(10)
            hits = search_goodreads(book['title'], book['authors'],
                                 series_name_position=list(book['series'].values())[0] if book['series'] else None,
                                 language=lang_code_to_name[book['lang_code']] if book['lang_code'] in lang_code_to_name else None)
        if hits:
            print(book['title'])
            print(' ' * 2 + book['url'])
            if len(hits) > 5:
                print(' ' * 2 + f'got {len(hits)} hits')
                print(' ' * 2 + f'showing first 5 results')
                hits = hits[:5]
            for hit in hits:
                print(' ' * 2 + hit["title"])
                print(' ' * 4 + hit['url'])
            print()


goodreads_graphql = GoodreadsGraphQL()
if __name__ == '__main__':
    main()

