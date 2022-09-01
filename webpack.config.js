const path = require('path');
const copy = require("copy-webpack-plugin");

module.exports = {
    entry: path.resolve(__dirname, 'src', 'extension.ts'),
    devtool: 'inline-source-map',
    mode: 'development',
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    plugins: [
        new copy({
            patterns: [
                {from: 'manifest.json', context: path.resolve(__dirname, 'src')},
                {from: 'icons/*.svg', context: path.resolve(__dirname, 'src')}
            ],
            options: {
                concurrency: 100,
            },
        }),
    ],
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
    },
    output: {
        filename: 'zipit.js',
        path: path.resolve(__dirname, 'dist'),
    },
};