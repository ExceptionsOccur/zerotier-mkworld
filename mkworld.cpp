/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2016  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This utility makes the World from the configuration specified below.
 * It probably won't be much use to anyone outside ZeroTier, Inc. except
 * for testing and experimentation purposes.
 *
 * If you want to make your own World you must edit this file.
 *
 * When run, it expects two files in the current directory:
 *
 * previous.c25519 - key pair to sign this world (key from previous world)
 * current.c25519 - key pair whose public key should be embedded in this world
 *
 * If these files do not exist, they are both created with the same key pair
 * and a self-signed initial World is born.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <algorithm>
#include <fstream>

#include "Constants.hpp"
#include "World.hpp"
#include "C25519.hpp"
#include "Identity.hpp"
#include "InetAddress.hpp"
#include "OSUtils.hpp"

using namespace ZeroTier;

int main(int argc,char **argv)
{
	// 传入 moon.json 文件路径名称
	std::vector<std::string> moonJsonFile(argc - 1);

	// 判断是否传入
	if (argc <= 1) {
		fprintf(stderr, "Usage: mkmoonworld [moon.json path] ..."
		ZT_EOL_S);
		return 1;
    }

    for (int i = 1; i < argc; i++) {
        moonJsonFile[i - 1] = argv[i];
    }

	std::string previous,current;
	if ((!OSUtils::readFile("previous.c25519",previous))||(!OSUtils::readFile("current.c25519",current))) {
		C25519::Pair np(C25519::generate());
		previous = std::string();
		previous.append((const char *)np.pub.data,ZT_C25519_PUBLIC_KEY_LEN);
		previous.append((const char *)np.priv.data,ZT_C25519_PRIVATE_KEY_LEN);
		current = previous;
		OSUtils::writeFile("previous.c25519",previous);
		OSUtils::writeFile("current.c25519",current);
		fprintf(stderr,"INFO: created initial world keys: previous.c25519 and current.c25519 (both initially the same)" ZT_EOL_S);
	}

	if ((previous.length() != (ZT_C25519_PUBLIC_KEY_LEN + ZT_C25519_PRIVATE_KEY_LEN))||(current.length() != (ZT_C25519_PUBLIC_KEY_LEN + ZT_C25519_PRIVATE_KEY_LEN))) {
		fprintf(stderr,"FATAL: previous.c25519 or current.c25519 empty or invalid" ZT_EOL_S);
		return 1;
	}
	C25519::Pair previousKP;
	memcpy(previousKP.pub.data,previous.data(),ZT_C25519_PUBLIC_KEY_LEN);
	memcpy(previousKP.priv.data,previous.data() + ZT_C25519_PUBLIC_KEY_LEN,ZT_C25519_PRIVATE_KEY_LEN);
	C25519::Pair currentKP;
	memcpy(currentKP.pub.data,current.data(),ZT_C25519_PUBLIC_KEY_LEN);
	memcpy(currentKP.priv.data,current.data() + ZT_C25519_PUBLIC_KEY_LEN,ZT_C25519_PRIVATE_KEY_LEN);

	// =========================================================================
	// EDIT BELOW HERE

	std::vector<World::Root> roots;

	const uint64_t id = ZT_WORLD_ID_EARTH;
	const uint64_t ts = 1567191349589ULL; // August 30th, 2019

	// 在 moon.json 文件里找到对应配置
	for (auto &path: moonJsonFile) {
        // Read in
        std::ifstream istream(path);
        nlohmann::json data;
        istream >> data;
        if (!data["roots"].is_array()) {
            fprintf(stderr, "moon.json has a wrong format!"
            ZT_EOL_S);
            return 2;
        }
        // 取 moon.json 里的值
        for (auto &root : data["roots"]) {
            roots.push_back(World::Root());
            roots.back().identity = Identity(root["identity"].get<std::string>().c_str());
            for (auto &addr : root["stableEndpoints"]) {
                std::string endpoint = addr.get<std::string>();
                fprintf(stdout, "Add world at endpoints: %s"
                ZT_EOL_S, endpoint.c_str());
                roots.back().stableEndpoints.push_back(InetAddress(endpoint.c_str()));
            }
        }
    }

	// END EDIT

	fprintf(stderr,"INFO: generating and signing id==%llu ts==%llu" ZT_EOL_S,(unsigned long long)id,(unsigned long long)ts);

	World nw = World::make(World::TYPE_PLANET,id,ts,currentKP.pub,roots,previousKP);

	Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> outtmp;
	nw.serialize(outtmp,false);
	World testw;
	testw.deserialize(outtmp,0);
	if (testw != nw) {
		fprintf(stderr,"FATAL: serialization test failed!" ZT_EOL_S);
		return 1;
	}

	OSUtils::writeFile("planet",std::string((const char *)outtmp.data(),outtmp.size()));
	fprintf(stderr,"INFO: planet written with %u bytes of binary world data." ZT_EOL_S,outtmp.size());

	fprintf(stdout,ZT_EOL_S);
	fprintf(stdout,"#define ZT_DEFAULT_WORLD_LENGTH %u" ZT_EOL_S,outtmp.size());
	fprintf(stdout,"static const unsigned char ZT_DEFAULT_WORLD[ZT_DEFAULT_WORLD_LENGTH] = {");
	for(unsigned int i=0;i<outtmp.size();++i) {
		const unsigned char *d = (const unsigned char *)outtmp.data();
		if (i > 0)
			fprintf(stdout,",");
		fprintf(stdout,"0x%.2x",(unsigned int)d[i]);
	}
	fprintf(stdout,"};" ZT_EOL_S);

	return 0;
}
