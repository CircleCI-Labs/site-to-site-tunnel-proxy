package proxy

import (
	"net"
	"testing"
)

func Test_pipe(t *testing.T) {
	t.Run("bidirectional copy", func(t *testing.T) {
		// Create two in-memory connection pairs.
		clientA, serverA := net.Pipe()
		clientB, serverB := net.Pipe()

		// Pipe serverA <-> clientB (the two "middle" ends).
		go pipe(serverA, clientB)

		// Write from clientA, read from serverB.
		msg := []byte("hello from A")
		go clientA.Write(msg) //nolint:errcheck

		buf := make([]byte, 64)
		n, err := serverB.Read(buf)
		if err != nil {
			t.Fatalf("read from B: %v", err)
		}
		if string(buf[:n]) != "hello from A" {
			t.Errorf("got %q, want %q", buf[:n], msg)
		}

		// Write from serverB, read from clientA.
		msg2 := []byte("hello from B")
		go serverB.Write(msg2) //nolint:errcheck

		n, err = clientA.Read(buf)
		if err != nil {
			t.Fatalf("read from A: %v", err)
		}
		if string(buf[:n]) != "hello from B" {
			t.Errorf("got %q, want %q", buf[:n], msg2)
		}

		// Close one side; both middle connections should close.
		clientA.Close()
		serverB.Close()
	})

	t.Run("closes both connections on EOF", func(t *testing.T) {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()

		done := make(chan struct{})
		go func() {
			pipe(a2, b1)
			close(done)
		}()

		// Close a1 → triggers EOF on a2 → Pipe closes both a2 and b1.
		a1.Close()
		<-done

		// b2 should now get an error when reading (b1 was closed by Pipe).
		buf := make([]byte, 1)
		_, err := b2.Read(buf)
		if err == nil {
			t.Fatal("expected error reading from b2 after pipe closed b1")
		}

		b2.Close()
	})
}
