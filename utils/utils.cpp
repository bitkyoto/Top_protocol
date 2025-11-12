#include <vector>
namespace utils {
    template <typename N>
    bool compare(const std::vector<N>& a, const std::vector<N>&b) {
        if (a.size() != b.size()) return false;
        for(size_t i = 0; i < a.size(); i++){
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
