package com.qezawat.iprocker.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * These tests pin the JSON contract with the Go core. If a struct tag in
 * internal/score changes without the Kotlin model following, the app would
 * silently show zeros; these catch that.
 */
class ModelsTest {

    @Test
    fun `candidate decodes a real go payload`() {
        val json = """
        {
          "ip": "104.25.228.176",
          "port": 443,
          "avg_latency_ms": 742.1,
          "min_latency_ms": 700.0,
          "jitter_ms": 21.4,
          "loss_percent": 0.0,
          "download_kbps": 360.2,
          "upload_kbps": 0.0,
          "colo": "FRA",
          "held_open": true,
          "websocket_ok": false,
          "tls_ok": true,
          "score": 71.3,
          "healthy": true,
          "notes": []
        }
        """.trimIndent()

        val c = IPRockerJson.decodeFromString<Candidate>(json)

        assertEquals("104.25.228.176:443", c.endpoint)
        assertEquals(71.3, c.score, 0.01)
        assertEquals(360.2, c.downloadKbps, 0.01)
        assertEquals(0.0, c.uploadKbps, 0.01)
        assertTrue(c.healthy)
        assertTrue(c.heldOpen)
        assertEquals("FRA", c.colo)
    }

    @Test
    fun `rejected candidate headline shows the reason`() {
        val json = """
        {
          "ip": "5.5.5.5",
          "port": 443,
          "healthy": false,
          "score": 0.0,
          "notes": ["connection reset during idle hold", "packet loss above threshold"]
        }
        """.trimIndent()

        val c = IPRockerJson.decodeFromString<Candidate>(json)
        assertFalse(c.healthy)
        assertEquals("connection reset during idle hold", c.headline)
    }

    @Test
    fun `rejected candidate with no notes shows generic headline`() {
        val json = """
        {
          "ip": "6.6.6.6",
          "port": 443,
          "healthy": false,
          "score": 0.0,
          "notes": []
        }
        """.trimIndent()

        val c = IPRockerJson.decodeFromString<Candidate>(json)
        assertFalse(c.healthy)
        assertEquals("measured edge", c.headline)
    }

    @Test
    fun `report separates usable from rejected`() {
        val json = """
        {
          "tested": 216,
          "hits": 23,
          "duration_ms": 36930,
          "candidates": [
            {"ip":"1.1.1.1","port":443,"healthy":true,"score":70.0},
            {"ip":"2.2.2.2","port":443,"healthy":true,"score":60.0},
            {"ip":"3.3.3.3","port":443,"healthy":false,"score":0.0}
          ]
        }
        """.trimIndent()

        val report = IPRockerJson.decodeFromString<ScanReport>(json)
        assertEquals(216L, report.tested)
        assertEquals(3, report.candidates.size)
        assertEquals(2, report.clean.size)
    }

    /** Unknown fields must not break decoding when the Go side gains a field. */
    @Test
    fun `unknown fields are ignored`() {
        val json = """{"ip":"9.9.9.9","port":443,"score":1.0,"brand_new_field":"x"}"""
        val c = IPRockerJson.decodeFromString<Candidate>(json)
        assertEquals("9.9.9.9", c.ip)
    }
}
