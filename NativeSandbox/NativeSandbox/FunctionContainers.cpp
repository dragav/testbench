#include "pch.h"

using namespace FunctionContainers;

void FunctionContainerRepro::PrintArray(std::vector<Item> items)
{
    for (unsigned int i = 0; i < items.size(); i++)
    {
        std::cout << "items[" << i << "] = " << items[i].Value << "\n";
    }

}

bool FunctionContainerRepro::ModifyItem(std::vector<Item>& items, int oldVal, int newVal)
{
    bool bFound = false;
    auto ref = items;
    for (std::vector<Item>::iterator it = ref.begin(); it != ref.end(); ++it)
    {
        if (it->Value != oldVal)
            continue;

        it->Value = newVal;
        bFound = true;

        break;
    }

    std::cout << (bFound ? "" : "not ") << "found item " << oldVal << " in array\n";

    return bFound;
}

void FunctionContainerRepro::Repro()
{
    auto ctr2 = std::make_shared<FunctionContainer>(2);
    auto cb2 = std::make_shared<Callback>([ctr2]
    {
        std::cout << "\n\tcb invoked with " << ctr2->Value << "\n";
        return ctr2->Value;
    });

    auto ctr4 = std::make_shared<FunctionContainer>(4);
    auto cb4 = std::make_shared<Callback>([ctr4]
    {
        std::cout << "\n\tcb invoked with " << ctr4->Value << "\n";
        return ctr4->Value;
    });

    std::vector<CallbackSPtr> fnVector;
    fnVector.push_back(cb2);
    fnVector.push_back(cb4);

    int idx = 0;
    for (auto cb : fnVector)
    {
        std::cout << "invoking from iterator, idx: " << idx++;
        (*cb)();
    }


    std::vector<Item>   items;
    for (int i = 0; i < 10; i++)
    {
        items.push_back(Item(i));
    }

    std::cout << "before modifying..\n";
    PrintArray(items);

    ModifyItem(items, 3, 10);

    std::cout << "after modifying..\n";
    PrintArray(items);
}