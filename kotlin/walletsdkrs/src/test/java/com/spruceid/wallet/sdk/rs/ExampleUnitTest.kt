package com.spruceid.wallet.sdk.rs

import org.junit.Test

import org.junit.Assert.*

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class UniffiUnitTest {
    @Test
    fun uniffiFunction() {
        assertEquals(helloFfi(), "Hello from Rust!")
    }
}