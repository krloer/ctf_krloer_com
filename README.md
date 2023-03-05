# Static Website Source for https://ctf.krloer.com

The page is built with Hugo, and the relevant documentation can be found here:
- [Hugo docs](https://gohugo.io/)
- [Learn theme docs](https://learn.netlify.app/en)

The theme includes support for a lot of cool features:
- Syntax Highlighting
- [Tabs](https://learn.netlify.app/en/shortcodes/tabs/)
- [File attachments](https://learn.netlify.app/en/shortcodes/attachments/)
- [Notices](https://learn.netlify.app/en/shortcodes/notice/)
- [Tags](https://learn.netlify.app/en/cont/tags/)

## How to...
### Run the site locally

1. Install hugo
  - Get it through your package manager
  - Or read [the install guide](https://gohugo.io/installation/)
2. Run the local server
  - `hugo serve`
  - The server will automatically refresh whenever a page is saved
  - The server window will print any warnings or errors
  - The site will be visible to you on http://localhost:1313

### Add a new CTF(Competition)

1. `hugo create --kind ctf writeups/COMPNAME/_index.md`, where _COMPNAME_ is the name of the event
2. Edit the file `content/writeups/COMPNAME/_index.md` in your favorite editor.
  - Look at other competitions for inspiration
  - Include a short description and some useful links

### Add a new challenge

1. Create a competition as described above.
2. `hugo create writeups/COMPNAME/CHALL/index.md`
3. Edit the file `content/writeups/COMPNAME/CHALL/index.md`
  - The file consists of two parts:
    - The "front matter" described in the Hugo documentation
    - A main section in markdown
4. Put images in `content/writeups/COMPNAME/CHALL/images`
5. Put attachments in `content/writeups/COMPNAME/CHALL/files`

Remember to look at existing pages to learn how to use images and attachments.

### Deploy the site

The site is configured with GitHub Actions, to automatically deploy to Github Pages.
To push the page to production, simply push or merge to the main branch.

```


(Imagaes used are normally created by me. Exceptions include the logo/favicon, which is [licensed by ReShot](https://www.reshot.com/license/))
