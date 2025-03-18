You can add styles, change images, or render custom HTML. Place your content inside the [`/custom`](https://github.com/thedevs-network/kutt/blob/main/custom) folder according to below instructions.

#### How it works:

<a id="user-content-how-it-works"></a>[](#how-it-works)

The structure of the custom folder is like this:

```
custom/
├─ css/
│  ├─ custom1.css
│  ├─ custom2.css
│  ├─ ...
├─ images/
│  ├─ logo.png
│  ├─ favicon.ico
│  ├─ ...
├─ views/
│  ├─ partials/
│  │  ├─ footer.hbs
│  ├─ 404.hbs
│  ├─ ...
```

- **css**: Put your CSS style files here. ([View example →](https://github.com/thedevs-network/kutt-customizations/tree/main/themes/crimson/css))
    - You can put as many style files as you want: `custom1.css`, `custom2.css`, etc.
    - If you name your style file `styles.css`, it will replace Kutt's original `styles.css` file.
    - Each file will be accessible by `<your-site.com>/css/<file>.css`
- **images**: Put your images here. ([View example →](https://github.com/thedevs-network/kutt-customizations/tree/main/themes/crimson/images))
    - Name them just like the files inside the [`/static/images/`](https://github.com/thedevs-network/kutt/blob/main/static/images) folder to replace Kutt's original images.
    - Each image will be accessible by `<your-site.com>/images/<image>.<image-format>`
- **views**: Custom HTML templates to render. ([View example →](https://github.com/thedevs-network/kutt-customizations/tree/main/themes/crimson/views))
    - It should follow the same file naming and folder structure as [`/server/views`](https://github.com/thedevs-network/kutt/blob/main/server/views)
    - Although we try to keep the original file names unchanged, be aware that new changes on Kutt might break your custom views.
