# Description
AES implementation in Common Lisp.

- 32-bit data types for AES core (64-bit implementation could not remove consing in the core functions.)
- optimization with pre-calculated tables.

# Performance
Lisp Version: sbcl-1.1.8-x86-64-darwin

## Clock cycles per byte
<table>
<tr><th></th> <th>2.26 GHz Intel Core 2 Duo</th> <th>2.8 GHz Intel i7</th></tr>
<tr><td>AES-128</td> <td>-</td> <td>280</td></tr>
<tr><td>AES-192</td> <td>-</td> <td>310</td></tr>
<tr><td>AES-256</td> <td>-</td> <td>340</td></tr>
</table>

## Consing in bytes per 128 bit block
<table>
<tr><th></th> <th>bytes</th></tr>
<tr><td>AES-128</td> <td>490</td></tr>
<tr><td>AES-192</td> <td>490</td></tr>
<tr><td>AES-256</td> <td>490</td></tr>
</table>
