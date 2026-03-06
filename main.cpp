#include <bits/stdc++.h>
using namespace std;
using namespace chrono;

// ---------- Utility ----------
string toLower(string s) {
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ---------- Load Patterns ----------
vector<string> loadPatterns() {
    vector<string> patterns;
    ifstream file("patterns.txt");
    string line;
    while (getline(file, line)) {
        patterns.push_back(toLower(line));
    }
    return patterns;
}

// ---------- LIST IDS ----------
void runListIDS() {
    vector<string> patterns = loadPatterns();

    ifstream input("cloud_in.txt");
    ofstream clean("cloud_out.txt");
    ofstream quarantine("quarantine.txt");
    ofstream alerts("alerts.txt");

    string line;
    int lineNo = 0;

    auto start = high_resolution_clock::now();

    while (getline(input, line)) {
        lineNo++;
        string temp = toLower(line);
        bool malicious = false;

        for (auto &p : patterns) {
            if (temp.find(p) != string::npos) {
                alerts << "[ALERT] Pattern: " << p
                       << " at line " << lineNo << "\n";
                malicious = true;
            }
        }

        if (malicious) quarantine << line << "\n";
        else clean << line << "\n";
    }

    auto end = high_resolution_clock::now();

    cout << "List IDS Done\n";
    cout << "Time: " << duration<double>(end - start).count() << " sec\n";
}

// ---------- HASH IDS ----------
void runHashIDS() {
    unordered_set<string> patterns;
    ifstream pat("patterns.txt");
    string s;

    while (getline(pat, s)) {
        patterns.insert(toLower(s));
    }

    ifstream input("cloud_in.txt");
    ofstream clean("cloud_out.txt");
    ofstream quarantine("quarantine.txt");
    ofstream alerts("alerts.txt");

    string line;
    int lineNo = 0;

    auto start = high_resolution_clock::now();

    while (getline(input, line)) {
        lineNo++;
        string temp = toLower(line);
        bool malicious = false;

        for (auto &p : patterns) {
            if (temp.find(p) != string::npos) {
                alerts << "[ALERT] Pattern: " << p
                       << " at line " << lineNo << "\n";
                malicious = true;
            }
        }

        if (malicious) quarantine << line << "\n";
        else clean << line << "\n";
    }

    auto end = high_resolution_clock::now();

    cout << "Hash IDS Done\n";
    cout << "Time: " << duration<double>(end - start).count() << " sec\n";
}

// ---------- TRIE (Aho-Corasick) ----------
struct Node {
    map<char, Node*> next;
    Node* fail = NULL;
    vector<string> output;
};

Node* root;

void insert(string pattern) {
    Node* node = root;
    for (char c : pattern) {
        if (!node->next[c])
            node->next[c] = new Node();
        node = node->next[c];
    }
    node->output.push_back(pattern);
}

void build() {
    queue<Node*> q;

    for (auto &p : root->next) {
        p.second->fail = root;
        q.push(p.second);
    }

    while (!q.empty()) {
        Node* curr = q.front(); q.pop();

        for (auto &p : curr->next) {
            char c = p.first;
            Node* child = p.second;

            Node* f = curr->fail;
            while (f && !f->next[c])
                f = f->fail;

            child->fail = (f) ? f->next[c] : root;

            for (auto &x : child->fail->output)
                child->output.push_back(x);

            q.push(child);
        }
    }
}

bool searchTrie(string text, int lineNo, ofstream &alerts) {
    Node* node = root;
    bool found = false;

    for (int i = 0; i < text.size(); i++) {
        char c = text[i];

        while (node && !node->next[c])
            node = node->fail;

        if (!node) {
            node = root;
            continue;
        }

        node = node->next[c];

        for (auto &pattern : node->output) {
            alerts << "[ALERT] Pattern: " << pattern
                   << " at line " << lineNo << "\n";
            found = true;
        }
    }
    return found;
}

void runTrieIDS() {
    root = new Node();

    ifstream pat("patterns.txt");
    string s;

    while (getline(pat, s)) {
        insert(toLower(s));
    }

    build();

    ifstream input("cloud_in.txt");
    ofstream clean("cloud_out.txt");
    ofstream quarantine("quarantine.txt");
    ofstream alerts("alerts.txt");

    string line;
    int lineNo = 0;

    auto start = high_resolution_clock::now();

    while (getline(input, line)) {
        lineNo++;
        string temp = toLower(line);

        bool malicious = searchTrie(temp, lineNo, alerts);

        if (malicious) quarantine << line << "\n";
        else clean << line << "\n";
    }

    auto end = high_resolution_clock::now();

    cout << "Trie IDS Done\n";
    cout << "Time: " << duration<double>(end - start).count() << " sec\n";
}

// ---------- MAIN ----------
int main() {
    int choice;

    cout << "===== IoT IDS System =====\n";
    cout << "1. List IDS\n";
    cout << "2. Hash IDS\n";
    cout << "3. Trie IDS (Aho-Corasick)\n";
    cout << "Enter choice: ";
    cin >> choice;

    if (choice == 1) runListIDS();
    else if (choice == 2) runHashIDS();
    else if (choice == 3) runTrieIDS();
    else cout << "Invalid choice\n";

    return 0;
}
