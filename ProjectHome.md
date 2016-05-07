I had been looking over the internet and didn't find a single free implementation for POP3 using SSL written for use with .NET applications. All of them were either sharewares or were commercial libraries. The only free library I found was OpenPOP. Now this library does all the fancy stuff like breaking your email into headers and body and stuff and also download attachments, however, it misses the point at one stage: SSL.

So I decided to write my own library for POP3 using SSL and I decided that my library should do ONLY SSL, cause that is where my library stands apart from the commercial tools. :) It is still primitive and does not do the fancy stuff like OpenPOP but it works.

**Please use the following path for checkout of source instead of the one mentioned in Downloads section:**

**http://pop3ssl.googlecode.com/svn/trunk/pop3SSL          for dll source**

**http://pop3ssl.googlecode.com/svn/trunk/pop3SSLTest     for test solution**

