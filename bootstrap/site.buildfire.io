Toggle navigation
Toggle navigation
DocumentationBlackfire for PHPTraining ResourcesPHP Code Performance ExplainedChapter 8 - Profiling all the Things
Chapter 8 - Profiling all the Things
Using the Blackfire Browser Extension
Using the Blackfire CLI
Profiling HTTP Requests from the CLI
Profiling CLI Commands
How does Blackfire work?
Auto Instrumentation
Conclusion
Ready to take it to the next level? Profiling HTTP GET requests is pretty cool, but you can use Blackfire to profile so much more: AJAX requests, form submissions, POST, PUT, and DELETE requests… you can even use Blackfire to profile CLI scripts.

Using the Blackfire Browser Extension
The browser extension’s big red “Profile!” button is rather straight-forward to use.

Now click below it: “Profile all Requests”. With a simple Start/Stop action, Blackfire will profile all requests which will be generated while you browse your website.

The icing on the cake: when we say “all requests”, that means no matter what domain they are on! For instance, if an Ajax request in your application hits another domain where you installed Blackfire as well, that request will also be profiled!

Using the Blackfire CLI
Profiling complex requests or CLI scripts can also be done using the blackfire command line tool, which was installed along with the Blackfire agent in a previous chapter. Confirm that everything works fine by running the following command:

1
blackfire config --dump
 
You should see the current configuration with your client-id and client-token (if not, run blackfire config and use your personal client credentials).

Profiling HTTP Requests from the CLI
Let’s profile the GitList homepage, but this time from the command line:

1
blackfire curl https://gitlist.demo.blackfire.io/
 
This command does the exact same thing as the browser extension, but from the command line: first you see a progress bar, followed by a profile summary and a link to the full profile:

1
2
3
4
5
6
7
8
9
Profiling: [########################################] 10/10
Blackfire cURL completed
Profile URL: https://blackfire.io/profiles/9ee9de4b-b086-4986-9d0b-53a9251001eb/graph

Wall Time    14.7ms
CPU Time     10.6ms
I/O Time     4.06ms
Memory       1.66MB
Network         n/a
Under the hood, blackfire curl uses cURL to issue HTTP requests to your servers and, therefore, supports all cURL features, making it very powerful. You must have cURL installed in order for this to work.

You can also use wget or any other tools able to make HTTP requests, but the process is more manual as described later in this chapter.

Now, let’s profile the GitList search engine, which is a POST request.

Go to https://fix2-ijtxpsladv67o.eu.platform.sh/Twig/ in Google Chrome, open the “Network” tab of the Browser’s Developer Tools (View > Developer > Developer Tools), and search for “loader” in the search box:

/docs/gitlist-search-engine.png
Look for the POST request sent by the browser by using the “Doc” filter (see the image above), right-click on the page name and select “Copy as cURL”:

/docs/gitlist-copy-as-curl.png
Using the browser to get the exact URL to profile is very convenient. Now, from your console, type “blackfire –samples=1” and paste the copied URL:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
blackfire --samples=1 curl 'https://fix2-ijtxpsladv67o.eu.platform.sh/Twig/tree/1.x/search' \
    -H 'Origin: https://fix2-ijtxpsladv67o.eu.platform.sh' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'Accept-Language: en-US,en;q=0.8,fr;q=0.6' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' \
    -H 'Cache-Control: max-age=0' -H 'Referer: https://fix2-ijtxpsladv67o.eu.platform.sh/Twig/' \
    -H 'Connection: keep-alive' -H 'DNT: 1' --data 'query=loader' --compressed
 
Note that using --samples=1 is safer as it avoids running several iterations of a non-GET HTTP request that might have side effects.

The generated profile should look something like this:


The Process runs take most of the time but the Twig_Template::getAttribute() method is called 2500+ times for 13% of the total time. Twig_Template::getAttribute() being the bottleneck is typical of a Twig application. Could the Twig C extension improve the performance? It depends… who knows? Probably? We are using Blackfire now, so we know. Stop guessing and measure. Make an informed decision.

That’s the typical workflow for non-GET HTTP requests like POST requests or Ajax requests. As an exercise, generate a profile for the Ajax requests sent when going to the Twig project “Network” page.

Profiling HTTP APIs is no different from profiling regular HTTP web requests, but a tool like httpie might simplify commands a lot. Read how you can use httpie with Blackfire.

Generate JSON representation of Profiles and Comparisons

The Blackfire command line tool --json option outputs a JSON representation of profiles and comparisons. It allows for simple automation tools to be developed on top of Blackfire.

Profiling CLI Commands
The Blackfire command line tool can be used to profiles CLI scripts via the run command:

1
blackfire run php -r 'echo "Hello World!";'
The output looks like before:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
Hello World!

Blackfire Run completed
Profile URL: https://blackfire.io/profiles/01e44337-ae51-465b-95ce-fb5fff3f73b7/graph

Wall Time     399µs
CPU Time      395µs
I/O Time        4µs
Memory       66.9KB
Network         n/a
The call graph for this profile is not that interesting but notice that “Hello World!” is displayed only once. By default, Blackfire only runs the code once for command line scripts. You can change this behavior using the --samples option:

1
blackfire --samples=5 run php -r 'echo "Hello World!";'
To make profiling from the command line more exciting, let’s run PHP Mess detector on Twig. PHP Mess Detector is a nice static analysis tool that tries to find potential problems in your code by using the raw metrics measured by PHP Depend.

Download phpmd version 2.2.1 as a phar, and execute it on the Twig source code like this:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
blackfire run php phpmd.phar /path/to/Twig/lib/ text cleancode

Blackfire Run completed
Profile URL: https://blackfire.io/profiles/452155e7-435b-438d-a84e-3249ee1cfafa/graph

Wall Time     18.1s
CPU Time      17.7s
I/O Time      441ms
Memory         42MB
Network         n/a
blackfire run supports any methods of running PHP scripts, from the standard php script.php, to using phars and executable scripts via a shebang (i.e. #!/usr/bin/env php).

If you run the command again, the code is going to run a lot faster, around 9 seconds, as phpmd uses a cache by default, stored under ~/.pdepend. This second run is our baseline.

Can we do better than 9 seconds? You’ve probably already spotted three potential issues: the unserialize() function is called 4,500+ times, and these calls account for more than two-thirds of the inclusive time. As unserialize() is a built-in PHP function, its exclusive time cannot be optimized. What about its children? The ASTNode::__wakeup() method is called 825,000+ times and the special “Garbage Collection” node takes 20% of the total time.

Blackfire is the only PHP profiler that gives detailed information about PHP garbage collector behavior.

As we cannot modify the .phar file easily, clone the phpmd repository and run Composer to install its dependencies:

1
2
3
4
git clone https://github.com/phpmd/phpmd.git
cd phpmd
git checkout -b 2.2.1 2.2.1
composer install
By default, the src/bin/phpmd script uses an in-memory cache, so switch to the file cache strategy used by the phar file by editing the pdepend.xml.dist configuration file:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
diff --git a/pdepend.xml.dist b/pdepend.xml.dist
index 5d02cd2..384e827 100644
--- a/pdepend.xml.dist
+++ b/pdepend.xml.dist
@@ -5,7 +5,7 @@
     xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">
     <config>
         <cache>
-            <driver>memory</driver>
+            <driver>file</driver>
         </cache>
     </config>
Time to create a profile, after having primed the cache:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
# prime the cache
php src/bin/phpmd /path/to/Twig/lib/ text cleancode

# create a profile
blackfire run php src/bin/phpmd /path/to/Twig/lib/ text cleancode

Blackfire Run completed
Profile URL: https://blackfire.io/profiles/f2ac6fc7-5c81-415d-97a6-49249a88abe6/graph

Wall Time     9.27s
CPU Time      8.86s
I/O Time      412ms
Memory         40MB
Network         n/a
Adding a cache to FileCacheDriver::restoreFile(), the unserialize() parent, avoids the unserialization of the same content over and over again:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
index dedde40..3ae43d9 100644
--- a/src/main/php/PDepend/Util/Cache/Driver/FileCacheDriver.php
+++ b/src/main/php/PDepend/Util/Cache/Driver/FileCacheDriver.php
@@ -180,11 +180,17 @@ class FileCacheDriver implements CacheDriver
      */
     public function restore($key, $hash = null)
     {
+        static $cache = array();
+
+        if (array_key_exists($key.'__'.$hash, $cache)) {
+            return $cache[$key.'__'.$hash];
+        }
+
         $file = $this->getCacheFile($key);
         if (file_exists($file)) {
-            return $this->restoreFile($file, $hash);
+            return $cache[$key.'__'.$hash] = $this->restoreFile($file, $hash);
         }
-        return null;
+        return $cache[$key.'__'.$hash] = null;
     }

     /**
After applying the patch, generate a new profile:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
blackfire run php src/bin/phpmd /path/to/Twig/lib/ text cleancode

Blackfire Run completed
Profile URL: https://blackfire.io/profiles/a41fd400-a3b6-492f-996f-38e2638f5327/graph

Wall Time      3.8s
CPU  Time     3.42s
I/O  Time     383ms
Memory         68MB
Network         n/a
Go to your Blackfire dashboard and compare the two profiles. You can see that the trade-off for having a faster code is a significant memory consumption increase. On the call graph, check that the main source of performance gains indeed comes from the drastic reduction of the number of unseralize() calls.

The other possible optimization comes from the special “Garbage Collection” node, which aggregates the resources consumed by PHP garbage collector. The garbage collection runs were not able to free up any memory (memory is 0 in the node details), so disabling it (via -d zend.enable_gc=0 on the CLI or gc_disable() in the PHP code) should be safe and should make our code even faster:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
blackfire run php -d zend.enable_gc=0 src/bin/phpmd /path/to/Twig/lib/ text cleancode

Blackfire Run completed
Profile URL: https://blackfire.io/profiles/342ef846-1de2-465c-bdf6-ef71bfb494c3/graph

Wall Time     2.54s
CPU  Time     2.19s
I/O  Time     346ms
Memory       68.1MB
Network         n/a
Indeed, this makes our code much faster without any memory consumption increase:


If you want to learn more about how garbage collecting works in PHP, please read Anthony Ferrara’s very detailed blog post.

You might be thinking that adding some cache is the only fix that can optimize an application, but that’s just because we have chosen our examples for their simplicity and the small code changes needed to make them faster.

In modern web applications, the common fixes are the reduction of the number of SQL queries and the number of external HTTP requests (API calls). Avoiding running the same code more than once is always a good idea anyway, and Blackfire lets you spot those occurrences. The inclusion of SQL queries and HTTP requests in your profiles is part of Blackfire’s premium and enterprise offerings and will be discussed in a coming chapter.

Profiling consumers and daemons

Profiling consumers and daemons is a totally different story as they run for a very long period of time. Auto-instrumentation, as done by Blackfire by default, cannot work in these cases. This is a topic for a future chapter, as we first need to learn about manually instrumenting your code.

How does Blackfire work?
Nobody likes using “magic” tools, at least not developers. At first, you probably thought Blackfire was magic because of some unasked and unanswered questions. How does Blackfire know when to instrument your code?

Would you like to understand how Blackfire works behind the scene? Read on. If you don’t like seeing magicians reveal their tricks, you can safely jump to the next section.

The main task of the browser extension and the blackfire command line tool is to trigger a profile by modifying the HTTP request or the CLI command, which in turns enables code instrumentation.

For HTTP requests, Blackfire adds a header, X-Blackfire-Query. The header value contains the profile configuration (like the number of samples, …) and a signature that identifies the user triggering the profile.

For CLI scripts, Blackfire defines an environment variable, BLACKFIRE_QUERY, and its value is the same as for HTTP requests.

When populating this HTTP header or environment variable, Blackfire appends a signature generated by Blackfire’s servers. When a request is received by your servers (or a command line script is run), the very first job of Blackfire is to check this signature. If the signature is invalid or the user is not authorized to run a profile (or if the value is missing altogether), instrumentation is disabled. To avoid leaking the fact that Blackfire is installed, the request is handled as if nothing happened.

In a nutshell, Blackfire overhead is negligible except when a profile is requested with an authorized signature in which case instrumentation is activated.

Using wget or any other HTTP tool instead of curl is no different. As blackfire run defines the BLACKFIRE_QUERY environment variable, use it to populate the X-Blackfire-Query header:

1
2
3
4
5
# replace blackfire curl
blackfire run sh -c 'curl -H "X-Blackfire-Query: $BLACKFIRE_QUERY" http://example.com/ > /dev/null'

# use wget instead of cURL
blackfire run sh -c 'wget --header="X-Blackfire-Query: $BLACKFIRE_QUERY" http://example.com/ > /dev/null'
For HTTP APIs, try httpie as a great alternative to cURL:

1
blackfire run sh -c 'http --json PUT example.org name=Fabien "X-Blackfire-Query:$BLACKFIRE_QUERY" > /dev/null'
A Word about Security

Blackfire signatures use a public/private key cryptographic system; the signatures use Ed25519 cryptography. Ed25519 generates short signatures that are embedded in HTTP headers while ensuring state-of-the-art security and performance (more about security in our Blackfire Security Model blog post).

Auto Instrumentation
No code change is needed to enable Blackfire. Everything happens from the outside as explained in the previous section.

Auto-instrumentation is very convenient, but it also allows Blackfire to profile way more than any other profiler as it can hook into the PHP engine very early on and stop the instrumentation very late; just a few examples of what Blackfire can profile thanks to auto-instrumentation: destructors, the PHP garbage collector, sessions, PHP file compilations, OPcache, and more.

Conclusion
The Blackfire command line tool is the best way to profile any code and do some basic automation. The profiling CLI commands and profiling HTTP requests cookbooks are a good reference for all supported options.

Time again to profile your own applications and see if you can find some more bottlenecks. If you get stuck making sense of the call graph, that’s the topic of the next chapter.

PRODUCT
Features
Pricing
Integrations
PHP Profiler
Python Profiler
Go Profiler
Documentation
Getting Started
SOLUTIONS
Performance Monitoring
Code Performance Profiler
Synthetic User Monitoring
CI/CD Integration
Code Quality Recommendations
Code Security Recommendations
Magento Code Profiler
Blackfire for Students
LEARN MORE
About
Blog
Careers
Customers
Supporting Open Source
Support
Service Status
Twitter @blackfireio
Github Github organization
Youtube Youtube channel
© 2014-2021 Blackfire is a trademark of Blackfire SAS. All rights reserved.  |  Terms of Use  |  Legal Notice  |  Privacy Policy  |  Cookie Policy  |  Cookie Management
This site is protected by reCAPTCHA and the Google Privacy Policy and Terms of Service apply.

