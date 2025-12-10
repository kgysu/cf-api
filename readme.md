# CF-API

Small app to manage your wow classic addons.


## How to

1. Set your cf api key as an ENV var like:
```sh
export CF-API-KEY="xxx"
```



2. Create a file called `addons.txt` with all the Addon-ID's from [courseforge](https://www.curseforge.com/) and place it in your wow installation addons folder.


Example:

```txt
12345
54321
123
```

Each Addon on one line.


3. Run the app and it will download all addons and place it in the current working directory. Also you can rerun the app at any time to update all addons.




