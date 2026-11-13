# blog.aslr.kr

Hexo blog using the [Cactus theme](https://github.com/probberechts/hexo-theme-cactus).

Requires Node.js 22.

To add your CV, place a PDF named `cv.pdf` in the `source` directory. The CV navigation link points to `/cv.pdf`.

```sh
npm ci
npm run server
npm run build
```

Pushes to `master` deploy through GitHub Actions. In repository Settings → Pages, set the build source to GitHub Actions and retain the custom domain `blog.aslr.kr`.
