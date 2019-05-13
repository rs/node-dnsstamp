module.exports = [{
    entry: './stamp.ts',
    output: { filename: 'stamp.js' },
    resolve: {
        extensions: [".ts", ".js"]
    },
    module: {
        rules: [
            { test: /\.tsx?$/, loader: "ts-loader" }
        ]
    },
    devtool: 'source-map',
    mode: 'development'
}];