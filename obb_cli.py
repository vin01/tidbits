#!/usr/bin/env python3

import fire
import requests
from bs4 import BeautifulSoup
import cfscrape

OBB_URL = "https://openbugbounty.org/search"

headers = {
    'User-Agent': 'obb-cli'
}

class SearchOBB(object):
    """A simple search tool for Open Bug Bounty."""

    def search(self, domains, raw=False, payload=False):
        """Return the search results from OBB for specified domain(s).

        domains : tuple
            Domain(s) to search. Either python list, tuple format or just comma separated values.
        raw: bool
            Print output in raw format with all fields.
        payload: bool
           Print payload info as well from the vulnerability report page(s) for unpatched vulnerabilities.
        """
        try:
            if isinstance(domains, str):
                domains=domains.split(',')
            for domain in domains:
                req = requests.get(
                    OBB_URL, params='search=%s&type=host' % (domain),
                    headers=headers
                )
                soup = BeautifulSoup(req.content, 'html.parser')
                data_table = soup.find(
                    'table', attrs={'class': 'latest-submissions-main-top'})
                if not data_table:
                    return "No results found."
                rows = data_table.find_all('tr')
                cookies = {}
                for row in rows:
                    cols = row.find_all('td')
                    link = cols[0].find('a')
                    if link:
                        href = "https://openbugbounty.org%s" % (
                            link.get('href'))
                    else:
                        href = "Report URL"
                    cols = [ele.text.strip() for ele in cols]
                    if raw:
                        print(cols)
                    else:
                        print('%-20s%-15s%-25s%-30s' %
                              (cols[0], cols[3], cols[4], href))
                    if cols[3] == "unpatched" and payload:
                        if not cookies:
                            tokens = cfscrape.get_tokens(href)
                            cookies = tokens[0]
                            headers['User-Agent']=tokens[1]
                        payload_req = requests.get(
                            href,
                            headers=headers,
                            cookies=cookies
                        )
                        payload_soup = BeautifulSoup(
                            payload_req.content, 'html.parser')
                        text_areas = payload_soup.find_all('textarea')
                        for text_area in text_areas:
                            print(text_area.text.strip(), end="\n\n")
        except requests.exceptions.RequestException as error:
            print(error)


if __name__ == '__main__':
    fire.Fire(SearchOBB)
