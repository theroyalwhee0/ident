declare module '@base32h/base32h' {
    function decodeBin(value:string):number[];
    function encodeBin(value:string|number[]|Buffer):string;
}
