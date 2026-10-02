// Retain cursor history, not the DOM/data for every visited page. Filtering is
// performed by the server before it returns a page and its next cursor.
class BlocklistPager {
    constructor() {
        this.version = 0;
        this.reset();
    }

    reset() {
        this.version++;
        this.index = 0;
        this.starts = [null];
        this.items = [];
        this.next = null;
    }

    begin(index = this.index) {
        if (!Number.isInteger(index) || index < 0) return null;
        let cursor;
        if (index < this.starts.length) cursor = this.starts[index];
        else if (index === this.index + 1 && this.next) cursor = this.next;
        else return null;
        return {version: ++this.version, index, cursor};
    }

    accept(request, page) {
        if (request.version !== this.version) return false;
        this.index = request.index;
        this.starts = this.starts.slice(0, request.index + 1);
        this.starts[request.index] = request.cursor;
        this.items = page.items;
        this.next = page.next || null;
        return true;
    }
}

if (typeof module !== 'undefined') module.exports = BlocklistPager;
