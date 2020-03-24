from bs4 import BeautifulSoup, NavigableString, Tag
import urllib.request
import re
import csv
import io

y1 = [];
y2 = [];
y3 = [];
y4 = [];
y5 = [];
y6 = [];
y7 = [];
y8 = [];
y9 = []
y10 = [];
y11 = [];
y12 = [];
y13 = [];
y14 = [];
y15 = [];
y16 = [];
y17 = []
f1 = []
p2 = []
page = urllib.request.urlopen("https://www.npmjs.com/advisories?page=34&perPage=20")
soup = BeautifulSoup(page, 'html.parser')
# # # # # #  Vulnerability Name/ Package Name / Date_of_Advisory / Severity /Status # # # # # # # # # # # # #

for link in soup.find_all('div', class_='b830cb24 f4 fw6 mb2'):
    k = [ele.text.strip() for ele in link]
    y1.append(k)
for body_child in soup.find_all('div', class_='_530f1ba4 fw6 mb2'):
    if isinstance(body_child, NavigableString):
        continue
    if isinstance(body_child, Tag):
        y2.append([body_child.text])
for body_child in soup.find_all('td', class_='_0509ba19 pa3 bt b--black-10 _55d8f1bb tc'):
    if isinstance(body_child, NavigableString):
        continue
    if isinstance(body_child, Tag):
        y3.append([body_child.text])
for link1 in soup.find_all('tr', class_='e3a88de2 _5fb3df3b'):
    k1 = [img["alt"] for img in link1.select("img[alt]")]
    result = [i.split(':') for i in k1]


    def Separate(m, n):
        return [m, n]


    result1 = Separate(result[0][1], result[1][1])
    y4.append(result1)

for x1 in range(0, len(y1)):
    y5.append(y1[x1] + y2[x1] + y3[x1])

# # # # # # # # # # Advisory # # # # # # # # # # # # #
# # # # # # # # # # Overview and Remediation # # # # # # # # # # # # #

for b1 in soup.find_all('div', class_='b830cb24 f4 fw6 mb2'):  # Get the Sub-link
    for e in b1:
        k = e.get('href')
        p2.append(k)
for j in p2:
    page1 = urllib.request.urlopen("https://www.npmjs.com" + str(j))
    Soup = BeautifulSoup(page1, 'html.parser')
    for text1 in Soup.find_all('p'):
        y6.append(text1.text.strip())
    page2 = urllib.request.urlopen("https://www.npmjs.com" + str(j) + "/versions")
    SOUP = BeautifulSoup(page2, 'html.parser')

    for i6 in SOUP.findAll('dl', attrs={'class': '_6d820777 flex mt0 mb3'}):  # Versions
        check = SOUP.findAll('dt', attrs={'class': '_2db260b4'})
        check1 = SOUP.findAll('dd', attrs={'class': 'c779e82c'})
        t1 = [new.text.strip() for new in check]
        t2 = [new1.text.strip() for new1 in check1]
    p = []
    m = []
    n = []
    space = " "
    for i5, val1 in enumerate(t1):
        for j5, val2 in enumerate(t2):
            if i5 == j5:
                p.extend([val1 + space + val2])
                k3 = ''.join(p)
    n.append(k3)
    k = n
    y12.append(k)

    if Soup.findAll('a', attrs={'href': re.compile("^https://github.com")}) and Soup.findAll('a', attrs={
        'href': re.compile("^https://snyk.io")}):
        for link11 in Soup.findAll('a', attrs={'href': re.compile("^https://github.com")}):
            for link22 in Soup.findAll('a', attrs={'href': re.compile("^https://snyk.io")}):
                y7.append(link11.get('href') + link22.get('href'))
    elif Soup.findAll('a', attrs={'href': re.compile("^https://github.com")}):  # Github
        for link2 in Soup.findAll('a', attrs={'href': re.compile("^https://github.com")}):
            y7.append(link2.get('href'))
    elif Soup.findAll('a', attrs={'href': re.compile("^https://snyk.io")}):
        for link3 in Soup.findAll('a', attrs={'href': re.compile("^https://snyk.io")}):  # Shell Command Injection
            y7.append(link3.get('href'))
    elif Soup.findAll('a', attrs={'href': re.compile("^https://hackerone.com")}):  # hacker
        for link4 in Soup.findAll('a', attrs={'href': re.compile("^https://hackerone.com")}):
            y7.append(link4.get('href'))
    else:
        y7.append('Null')

    for text2 in Soup.find_all('div', class_='a30ef028'):  # Published and Reported
        m1 = text2.text.strip()
        m2 = m1
        try:
            m3 = re.search('published(.*)', m2).group(1)  # Skip the String
        except:
            pass
        try:
            m3 = re.search('reported(.*)', m2).group(1)  # Skip the String
        except:
            pass
        y16.append(m3)

for x3 in range(0, len(y7)):  # Github Integration
    b = [y7[x3]]
    y13.append(b)

num1 = 0
num2 = 1
for x in range(0, 20):
    y15.append([y6[num1], y6[num2]])
    y17.append([y16[num1], y16[num2]])
    num1 = num1 + 2
    num2 = num2 + 2
    y8.append(y5[x] + y17[x] + y4[x])
    y14.append(y8[x] + y15[x] + y12[x] + y13[x])

with io.open("FinalSheet34.csv", 'a+', newline='', encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(y14)

'''
d1 = 0
d2 = 1
d3 = 2
f2 =[]
p1 = 0
p2 = 1
if len(y6) == 60:
    for c2 in range(0,20):
        n1 = y6[d1]
        n2 = y6[d2] + y6[d3]
        d1 = d1 + 3
        d2 = d2 + 3
        d3 = d3 + 3
        f1.append([n1, n2])
    # for c3 in range(0, 10):
    #     f2.append([f1[p1]],[f1[p2]])
    #     p1 = p1 + 2
    #     p2 = p2 + 2
    print(f1)
'''
